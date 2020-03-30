# pragma: nocover
# type: ignore
import html
import base64
import os
import urllib3
from django.conf import settings
from datetime import datetime, timedelta
from celery.task import BaseTask
from celery import shared_task
from zeep import Client
from contextlib import contextmanager

from zeep.transports import Transport
from zeep.wsse.signature import BinarySignature as Signature
from zeep.wsse import utils
from requests import Session
from typing import Dict, Any, Iterable

# GCSS dev environment certificate is not trusted
# TODO: explicitly trust their public cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GCSSWsseSignature(Signature):
    def apply(self, envelope, headers):
        security = utils.get_security_header(envelope)
        created = datetime.now()
        expired = created + timedelta(days=5)
        timestamp = utils.WSU("Timestamp")
        timestamp.append(
            utils.WSU("Created", created.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        )
        timestamp.append(
            utils.WSU("Expires", expired.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        )
        security.append(timestamp)
        return super().apply(envelope, headers)

    def verify(self, envelope: str) -> str:
        return envelope


class RetrieveDataTaskBase(BaseTask):
    public_cert_filename = "/home/ubuntu/selfsigned.key"
    private_key_filename = "/home/ubuntu/selfsigned.crt"
    service_name = None

    @contextmanager
    def get_client(self):
        session = Session()
        session.cert = (self.public_cert_filename, self.private_key_filename)
        session.verify = False
        # client constructor fetches wsdl
        client = Client(
            f"https://gcssmc-dv-int.dev.gcssmc.sde/gateway/services/${self.service_name}?wsdl",
            transport=Transport(session=session),
            wsse=GCSSWsseSignature(
                self.private_key_filename, self.public_cert_filename
            ),
        )
        yield client
        session.close()

    def should_next_page(self, response):
        return getattr(response, "remaining-records", 0) > 0

    def get_data_from_response(self, response):
        collection = getattr(response, f"{self.service_name}Collection")
        if not collection:
            return []
        return getattr(collection, f"{self.service_name}Record", [])

    def process_pages(self):
        page_size = getattr(settings, GCSS_PAGING_MAX, 10000)
        current_page = 0
        client = self.get_client()
        response = None
        with self.get_client() as client:
            while current_page == 0 or self.should_next_page(response):
                response = client.process(
                    outputType="SOAP",
                    nullElements="yes",
                    pagingSkip=current_page * page_size,
                    pagingMax=page_size,
                )
                yield response
                current_page += 1


class DocHistoryTask(RetrieveDataTaskBase):
    service_name = "br2MerDocHistory"

    def wsdl_to_document(self, item):
        data = {sdn: item.get("D")}
        return Document(**data)


@shared_task(bind=True, base=DocHistoryTask)
def update_documents(self):
    for page in self.process_pages():
        documents = [self.wsdl_to_document(item) for item in page]
        Document.objects.bulk_create(documents)
