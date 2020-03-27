import React from "react";
import EnterReceiptPage from "../EnterReceiptPage";
import LoadingIcon from "../LoadingIcon";
import { defaultApiResponse } from "solo-types";
import { render, fireEvent, wait } from "test-utils";

describe("EnterReceiptPage Component", () => {
  const fetchMock = jest.fn();
  const defaultDoc = defaultApiResponse.results[0];

  afterEach(() => {
    fetchMock.mockReset();
  });

  it("matches snapshot", async () => {
    fetchMock.mockResolvedValue(defaultApiResponse);
    const { asFragment, queryByText, getByText } = render(
      <EnterReceiptPage />,
      {
        authContext: {
          apiCall: fetchMock
        }
      }
    );
    const submitBtn = getByText("Search");
    fireEvent.click(submitBtn);
    await wait(() => {
      // wait for some data to render before checking snapshot
      expect(fetchMock).toHaveBeenCalled();
      expect(queryByText(defaultDoc.sdn)).toBeInTheDocument();
    });
    expect(asFragment()).toMatchSnapshot();
  });

  it("calls api and adds result to table when adding an sdn", async () => {
    fetchMock.mockResolvedValue(defaultApiResponse);
    const { queryByText, getByPlaceholderText, getByText } = render(
      <EnterReceiptPage />,
      {
        authContext: {
          apiCall: fetchMock
        }
      }
    );
    const inputField = getByPlaceholderText("SDN");
    const submit = getByText("Search");
    fireEvent.change(inputField, {
      target: { value: "somesdn" }
    });
    fireEvent.click(submit);
    await wait(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).toEqual(
        "/document/?sdn_exact=somesdn&exclude_status=D6T"
      );
      expect(queryByText(defaultDoc.part.nomen)).toBeInTheDocument();
    });
  });

  it("removes row from table when selecting remove button", async () => {
    const { getByPlaceholderText, getByText, container, queryByText } = render(
      <EnterReceiptPage />,
      {
        authContext: {
          apiCall: fetchMock
        }
      }
    );
    const inputField = getByPlaceholderText("SDN");
    const submit = getByText("Search");
    fireEvent.change(inputField, {
      target: { value: "wrongsdn" }
    });
    await wait(() => {
      expect(inputField).toHaveValue("wrongsdn");
    });
    fireEvent.click(submit);
    await wait(() => {
      expect(getByText("wrongsdn")).toBeInTheDocument();
    });
    const removeIcon = container.querySelector("button.usa-button") as Element;
    fireEvent.click(removeIcon);
    await wait(() => {
      expect(removeIcon).not.toBeInTheDocument();
      expect(queryByText("wrongsdn")).not.toBeInTheDocument();
    });
  });

  it("keeps sdn in table on fetch error", async () => {
    fetchMock.mockRejectedValue(new Error());
    const { queryByText, getByPlaceholderText, getByText } = render(
      <EnterReceiptPage />,
      {
        authContext: {
          apiCall: fetchMock
        }
      }
    );
    const inputField = getByPlaceholderText("SDN");
    const submit = getByText("Search");
    fireEvent.change(inputField, {
      target: { value: "badsdn" }
    });
    fireEvent.click(submit);
    await wait(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(queryByText(/^badsdn/)).toBeInTheDocument();
    });
  });

  it("handles sdn not found or empty response from api", async () => {
    fetchMock.mockResolvedValue({
      ...defaultApiResponse,
      results: []
    });
    const { getByText, getByPlaceholderText, queryByText, container } = render(
      <EnterReceiptPage />,
      {
        authContext: {
          apiCall: fetchMock
        }
      }
    );
    const inputField = getByPlaceholderText("SDN");
    fireEvent.change(inputField, {
      target: { value: "badsdn" }
    });
    await wait(() => {
      expect(inputField).toHaveValue("badsdn");
    });
    const submit = getByText("Search");
    fireEvent.click(submit);
    await wait(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(queryByText("badsdn")).toBeInTheDocument();
      const errorIcon = container.querySelector("svg.fa-exclamation-circle");
      expect(errorIcon).toBeInTheDocument();
    });
  });

  it("only updates associated sdn", async () => {
    fetchMock.mockResolvedValue({
      ...defaultApiResponse,
      results: [{ ...defaultDoc, sdn: "1234" }]
    });
    const { queryByText, queryAllByText, getByText } = render(
      <EnterReceiptPage />,
      {
        authContext: {
          apiCall: fetchMock
        }
      }
    );
    const submit = getByText("Search");
    fireEvent.click(submit);
    await wait(() => {
      expect(queryByText("1234")).toBeInTheDocument();
    });
    fetchMock.mockResolvedValue({
      ...defaultApiResponse,
      results: [
        {
          ...defaultDoc,
          sdn: "6789",
          part: { ...defaultDoc.part, nsn: "differentnsn" }
        }
      ]
    });
    fireEvent.click(submit);
    await wait(() => {
      expect(queryByText("1234")).toBeInTheDocument();
      expect(queryByText("6789")).toBeInTheDocument();
      expect(queryAllByText("differentnsn")).toHaveLength(1);
    });
  });
});

describe("LoadingIcon component", () => {
  it("renders loading icon when loading", async () => {
    const { asFragment } = render(<LoadingIcon loading error={false} />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders error icon on fetch error", async () => {
    const { asFragment } = render(
      <LoadingIcon loading={false} error={true} message="some error" />
    );
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders check icon on fetch success", async () => {
    const { asFragment } = render(
      <LoadingIcon loading={false} error={false} />
    );
    expect(asFragment()).toMatchSnapshot();
  });
});
