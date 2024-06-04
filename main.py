import os.path
import base64
import time

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
    except HttpError:
        print("Invalid label name or label already exists.")


def add_label(message_id, label_name):
    creds = get_credentials()
    try:
        label_id = get_label_id(label_name)
        service = build("gmail", "v1", credentials=creds)
        labels_to_add = {"addLabelIds": [label_id]}

        service.users().messages().modify(
            userId="me", id=message_id, body=labels_to_add
        ).execute()
    except HttpError as error:
        print(f"Error: {error}")


def get_thread_id(message_id):
    creds = get_credentials()
    service = build("gmail", "v1", credentials=creds)
    message = service.users().messages().get(userId="me", id=message_id).execute()
    return message["threadId"]


def decode_body(message):
    body = ""
    try:
        if "data" in message["payload"]["body"]:
            body = base64.urlsafe_b64decode(message["payload"]["body"]["data"]).decode(
                "utf-8"
            )
        elif "parts" in message["payload"]:
            for part in message["payload"]["parts"]:
                body += base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
    except KeyError as e:
        print(f"Error: {e}")
        body = ""
    return body


def check_email_bounced_status(thread_id: str) -> None:
    time.sleep(2)
    creds = get_credentials()
    service = build("gmail", "v1", credentials=creds)
    messages = (
        service.users()
        .messages()
        .list(userId="me", q="from:mailer-daemon@googlemail.com")
        .execute()
        .get("messages", [])
    )
    for msg in messages:
        if msg["threadId"] == thread_id:
            raise Exception("Email bounced back. Check email addresses again.")


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
        sent_message = (
            service.users().messages().send(userId="me", body=create_message).execute()
        )
        check_email_bounced_status(sent_message["threadId"])
    except HttpError as error:
        print(f"An error occurred: {error}")
        sent_message = None
    return sent_message


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
        return subject, sender, body


def get_emails_from_thread(thread_id):
    emails = []
    creds = get_credentials()
    service = build("gmail", "v1", credentials=creds)
    thread = service.users().threads().get(userId="me", id=thread_id).execute()
    messages = thread["messages"]
    for message in messages:
        if len(messages) > 1:
            subject = ""
            body = ""
            headers = message["payload"]["headers"]
            for header in headers:
                if header["name"] == "Subject":
                    subject = header["value"]
            body = decode_body(message)
            emails.append({"subject": subject, "body": body})
    return emails


def get_threads(label_name: str | None, to_email: str) -> list[str] | None:
    try:
        result = []
        if label_name:
            label_id = get_label_id(label_name)
        else:
            label_id = "INBOX"

        creds = get_credentials()
        service = build("gmail", "v1", credentials=creds)
        threads = (
            service.users()
            .threads()
            .list(maxResults=100, userId="me", q=f"to:{to_email}", labelIds=[label_id])
            .execute()
            .get("threads", [])
        )
        for thread in threads:
            thread_id = thread["id"]
            emails = get_emails_from_thread(thread_id)
            for email in emails:
                result.append(email)
        return result
    except HttpError as error:
        print(f"An error occurred: {error}")


def main():
    print("Python Script to Interact with Gmail")
    print("Would you like to: ")
    print("1) Send email")
    print("2) See your inbox")
    print("3) Get your recent threads")
    print("4) Create label")
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
        get_messages_obj = get_messages(message_no)
        print("\033[1;33;40mSubject: ", get_messages_obj[0])
        print("\033[1;33;40mFrom: ", get_messages_obj[1])
        print("Message: ", get_messages_obj[2])
        print("-" * 50)

    elif choice == 3:
        label_name = input("Enter the name of the label: ")
        to_email = input("Enter the email from which you want the threads: ")
        get_threads(label_name, to_email)
    elif choice == 4:
        label_name = input("Enter the name of the label: ")
        create_label(label_name)
    else:
        print("Wrong input.")


if __name__ == "__main__":
    main()
