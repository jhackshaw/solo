# pragma: nocover
import html
import base64
import os
from datetime import datetime, timedelta
from django.conf import settings
from celery import shared_task
from celery.task import BaseTask
from zeep import Client

from zeep.transports import Transport
from zeep.wsse.signature import BinarySignature as Signature
from zeep.wsse import utils
from requests import Session
from typing import Iterable, Any, List
from solo_rog_api.models import Document
from solo_rog_api.serializers import DocumentSerializer
from solo_rog_api.tasks import gcss_api_templates


class GCSSWsseSignature(Signature):
    def apply(self, envelope: str, headers: Iterable[Any]) -> Any:
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


class BaseGCSSTask(BaseTask):
    base_url = os.environ.get(
        "GCSS_BASE_SEVICE_URL", "https://gcssmc-dv-int.dev.gcssmc.sde/gateway/services/"
    )
    private_key_filename = "/home/ubuntu/.ssh/selfsigned.key"
    public_cert_filename = "/home/ubuntu/.ssh/selfsigned.crt"

    def __init__(self) -> None:
        self.client = self.make_client()

    def make_client(self) -> Client:
        session = Session()
        session.cert = (self.public_cert_filename, self.private_key_filename)
        session.verify = not settings.DEBUG

        return Client(
            self.service_url,
            transport=Transport(session=session),
            wsse=GCSSWsseSignature(
                self.private_key_filename, self.public_cert_filename
            ),
        )

    @property
    def service_url(self) -> str:
        return f"{self.base_url}{self.service_name}?wsdl"

    def xml_to_compressed_payload(self, xml: str) -> str:
        # placeholder until EXML conversion service is complete
        # response = requests.post(settings.EXML_CONVERTER_ENDPOINT, data=payload)
        # return base64.b64decode(response.content)
        return xml

    def xml_to_uncompressed_payload(self, xml: str) -> str:
        # GCSS uncompressed payload requires '<', and '>' to be
        # escaped with &lt; and &gt; respectively
        return html.escape(xml, quote=False)


class GCSSI42Task(BaseGCSSTask):
    service_name = "I009ShipmentReceiptsIn"


@shared_task(bind=True, base=GCSSI42Task)
def submit_d6t(self: GCSSI42Task, documents: Iterable[Document]) -> None:
    # serialize documents
    serialized = [
        DocumentSerializer(document).data
        for document in documents
    ]

    # convert documents to xml
    m_recs = [
        gcss_api_templates.I009_TEMPLATE_MREC.format(**document)
        for document in serialized
    ]
    wrapped_payload = gcss_api_templates.I009_TEMPLATE_WRAPPER.format(m_recs)

    # html quote xml
    quoted = self.xml_to_uncompressed_payload(wrapped_payload)

    # submit to gcss
    self.client.initiateUncompressed(input=quoted)
