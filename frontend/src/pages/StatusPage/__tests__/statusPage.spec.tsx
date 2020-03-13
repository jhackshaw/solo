import React from "react";
import { render, wait, fireEvent } from "test-utils";
import { defaultApiResponse } from "solo-types";
import StatusPage from "../StatusPage";

jest.mock("components/DocumentDetails", () => () => <div>testdetails</div>);
jest.mock("components/SelectFilterControls", () => () => (
  <div>filtercontrols</div>
));
jest.mock("components/Paginator", () => () => <div>paginator</div>);

// prevent snapshot tests from failing per day
jest.mock("date-fns", () => ({
  parseISO: () => "testiso",
  formatDistanceToNow: () => {
    return "some amount of time";
  }
}));

afterAll(() => {
  jest.restoreAllMocks();
});

describe("StatusPage component", () => {
  const fetchMock = jest.fn();

  beforeEach(() => {
    fetchMock.mockResolvedValue(defaultApiResponse);
  });

  afterEach(() => {
    fetchMock.mockReset();
  });

  it("matches snapshot", async () => {
    const { asFragment } = render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
      expect(asFragment()).toMatchSnapshot();
    });
  });

  it("requests documents from api on initial render", async () => {
    fetchMock.mockResolvedValue({
      ...defaultApiResponse,
      results: []
    });
    render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
      expect(fetchMock.mock.calls[0][0]).toEqual("/documents");
      expect(fetchMock.mock.calls[0][1]).toMatchObject({
        method: "GET"
      });
    });
  });

  it("shows document details when toggled", async () => {
    const { getByTitle, queryByText } = render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
    });
    const toggleBtn = getByTitle("Toggle Row Expanded");
    fireEvent.click(toggleBtn);
    await wait(() => {
      expect(queryByText("testdetails")).toBeInTheDocument();
    });
  });

  it("re-fetches documents on status_date table sort change", async () => {
    const { getByText } = render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
    });
    const lastUpdatedHeader = getByText(/^Last Updated/);
    fireEvent.click(lastUpdatedHeader);
    await wait(() => {
      // first call was on render, this is second
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(fetchMock.mock.calls[1][0]).toEqual("/documents?sort=status_date");
    });
    fireEvent.click(lastUpdatedHeader);
    await wait(() => {
      // sort by is now desc
      expect(fetchMock).toHaveBeenCalledTimes(3);
      expect(fetchMock.mock.calls[2][0]).toEqual(
        "/documents?sort=status_date&desc=true"
      );
    });
    fireEvent.click(lastUpdatedHeader);
    await wait(() => {
      // sort by is undefined
      expect(fetchMock).toHaveBeenCalledTimes(4);
      expect(fetchMock.mock.calls[3][0]).toEqual("/documents");
    });
  });

  it("re-fetches documents on sdn table sort change", async () => {
    const { getByText } = render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
    });
    const sdnHeader = getByText(/^SDN$/);
    fireEvent.click(sdnHeader);
    await wait(() => {
      // first call was on render, this is second
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(fetchMock.mock.calls[1][0]).toEqual("/documents?sort=sdn");
    });
    fireEvent.click(sdnHeader);
    await wait(() => {
      // sort by is now desc
      expect(fetchMock).toHaveBeenCalledTimes(3);
      expect(fetchMock.mock.calls[2][0]).toEqual(
        "/documents?sort=sdn&desc=true"
      );
    });
  });

  it("re-fetches documents on sdn table sort change", async () => {
    const { getByText } = render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
    });
    const serviceReqHeader = getByText(/^Service Request/);
    fireEvent.click(serviceReqHeader);
    await wait(() => {
      // first call was on render, this is second
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(fetchMock.mock.calls[1][0]).toEqual(
        "/documents?sort=service_request"
      );
    });
    fireEvent.click(serviceReqHeader);
    await wait(() => {
      // sort by is now desc
      expect(fetchMock).toHaveBeenCalledTimes(3);
      expect(fetchMock.mock.calls[2][0]).toEqual(
        "/documents?sort=service_request&desc=true"
      );
    });
  });

  it("renders 25 fake documents on fetch error for now", async () => {
    fetchMock.mockRejectedValue(new Error());
    const { getAllByTitle } = render(<StatusPage />, {
      authContext: {
        apiCall: fetchMock
      }
    });
    await wait(() => {
      expect(fetchMock).toHaveBeenCalled();
    });
    const allRowToggles = getAllByTitle("Toggle Row Expanded");
    expect(allRowToggles.length).toEqual(25);
  });
});