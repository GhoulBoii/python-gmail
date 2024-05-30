import os.path
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.message import EmailMessage
from bs4 import BeautifulSoup

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]


def get_credentials():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def get_label_id(label_name):
    creds = get_credentials()

    try:
        service = build("gmail", "v1", credentials=creds)
        labels = service.users().labels().list(userId="me").execute()
        for label in labels["labels"]:
            if label["name"] == label_name:
                return label["id"]
        return None
    except Exception as error:
        print(f"Error: {error}")


def create_label(label_name):
    creds = get_credentials()

    try:
        service = build("gmail", "v1", credentials=creds)
        label_id = get_label_id(label_name)

        label_body = {"addLabelIds": [label_id]}
        service.users().labels().create(userId="me", body=label_body).execute()

        print("Label has been created")
    except HttpError as error:
        print(f"Error: {error}")


def add_label(message_id, label_name):
    creds = get_credentials()
    try:
        service = build("gmail", "v1", credentials=creds)
        labels_to_add = {"addLabelIds": label_name}

        service.users().messages().modify(
            userId="me", id=message_id, body=labels_to_add
        ).execute()
        print("Message has been added to label")
    except HttpError as error:
        print(f"Error: {error}")


def send_message(from_email, to_email, subject, body, html_code):
    creds = get_credentials()

    try:
        service = build("gmail", "v1", credentials=creds)
        message = EmailMessage()

        body += html_code
        message.set_content(body, subtype="html")

        message["To"] = to_email
        message["From"] = from_email
        message["Subject"] = subject

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {"raw": encoded_message}
        # pylint: disable=E1101
        send_message = (
            service.users().messages().send(userId="me", body=create_message).execute()
        )
        print(f'Email has been sent with the following id: {send_message["id"]}')
    except HttpError as error:
        print(f"An error occurred: {error}")
        send_message = None
    return send_message


def get_messages(message_no):
    creds = get_credentials()
    service = build("gmail", "v1", credentials=creds)
    result = (
        service.users().messages().list(maxResults=message_no, userId="me").execute()
    )
    messages = result.get("messages")
    for msg in messages:
        # Get the message from its id
        txt = service.users().messages().get(userId="me", id=msg["id"]).execute()
        # Get value of 'payload' from dictionary 'txt'
        payload = txt["payload"]
        headers = payload["headers"]

        # Look for Subject and Sender Email in the headers
        for d in headers:
            if d["name"] == "Subject":
                subject = d["value"]
            if d["name"] == "From":
                sender = d["value"]

        # The Body of the message is in Encrypted format. So, we have to decode it.
        # Get the data and decode it with base 64 decoder.
        parts = payload.get("parts")[0]
        data = parts["body"]["data"]
        data = data.replace("-", "+").replace("_", "/")
        decoded_data = base64.b64decode(data)

        # Now, the data obtained is in lxml. So, we will parse
        # it with BeautifulSoup library
        soup = BeautifulSoup(decoded_data, "lxml")
        body = soup.body()

        # Printing the subject, sender's email and message
        print("\033[1;33;40mSubject: ", subject)
        print("\033[1;33;40mFrom: ", sender)
        print("Message: ", body)
        print(
            "\n\n---------------------------------------------------------------------\n\n"
        )


def get_threads_in_label(label_name: str) -> None:
    try:
        creds = get_credentials()
        service = build("gmail", "v1", credentials=creds)
        label_id = get_label_id(label_name)
        threads = (
            service.users()
            .threads()
            .list(maxResults=100, userId="me", labelIds=[label_id])
            .execute()
            .get("threads", [])
        )
        for thread in threads:
            tdata = (
                service.users().threads().get(userId="me", id=thread["id"]).execute()
            )
            nmsgs = len(tdata["messages"])
            if nmsgs > 1:
                print("NEW THREAD STARTING!")
                msg = tdata["messages"][0]["payload"]
                subject = ""
                email_body = ""

                for header in msg["headers"]:
                    if header["name"] == "Subject":
                        subject = header["value"]
                        break

                try:
                    data = msg["body"]["data"]
                    data = data.replace("-", "+").replace("_", "/")
                    decoded_data = base64.b64decode(data)
                    soup = BeautifulSoup(decoded_data, "lxml")
                    email_body = soup.body()

                except KeyError:
                    print("No body found")

                if subject:  # skip if no Subject line
                    print(f"- {subject}\n\n{email_body}")
            return threads

    except HttpError as error:
        print(f"An error occurred: {error}")


def get_threads() -> None:
    try:
        creds = get_credentials()
        service = build("gmail", "v1", credentials=creds)
        threads = (
            service.users()
            .threads()
            .list(maxResults=100, userId="me")
            .execute()
            .get("threads", [])
        )
        for thread in threads:
            tdata = (
                service.users().threads().get(userId="me", id=thread["id"]).execute()
            )
            nmsgs = len(tdata["messages"])
            if nmsgs > 1:
                print("NEW THREAD STARTING!")
                msg = tdata["messages"][0]["payload"]
                subject = ""
                email_body = ""

                for header in msg["headers"]:
                    if header["name"] == "Subject":
                        subject = header["value"]
                        break

                try:
                    data = msg["body"]["data"]
                    data = data.replace("-", "+").replace("_", "/")
                    decoded_data = base64.b64decode(data)
                    soup = BeautifulSoup(decoded_data, "lxml")
                    email_body = soup.body()

                except KeyError:
                    print("No body found")

                if subject:  # skip if no Subject line
                    print(f"- {subject}\n\n{email_body}")
            return threads

    except HttpError as error:
        print(f"An error occurred: {error}")


def main():
    print("Python Script to Interact with Gmail")
    print("Would you like to: ")
    print("1) Send email")
    print("2) See your inbox")
    print("3) Get your recent threads")
    print("4) Create label")
    print("5) Get your recent threads in a label")
    choice = int(input())

    if choice == 1:
        from_email = input("Enter your email address: ")
        to_email = input("Enter the receiver's email address: ")
        subject = input("Enter the subject of the email: ")
        body = input("Enter the body of the email:\n")
        html_code = input("Enter any html code: ")
        send_message(from_email, to_email, subject, body, html_code)
    elif choice == 2:
        message_no = int(
            input(
                "Enter number of messages you would like to see from your inbox (latest first): "
            )
        )
        get_messages(message_no)
    elif choice == 3:
        get_threads()
    elif choice == 4:
        label_name = input("Enter the name of the label: ")
        create_label(label_name)
    elif choice == 5:
        label_name = input("Enter tha name of the label: ")
        get_threads_in_label(label_name)
    else:
        print("Wrong input.")


if __name__ == "__main__":
    main()
