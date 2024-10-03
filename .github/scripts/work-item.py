import click
import re
import sys
import requests
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication


@click.command()
@click.argument('token', required=True)
@click.argument('url', required=True)
@click.option('--validate-only', default=False, is_flag=True)
@click.option('--organization', default='https://microsoft.visualstudio.com')
@click.option('--project', default='HyperVCloud')
@click.option('--debug', default=False, is_flag=True)
def main(token: str, url: str, validate_only: bool, organization: str, project: str, debug: bool):
    try:
        # Extract work items from description
        description = sys.stdin.read()
        work_items = find_work_item_numbers(description)

        if not work_items:
            print(f'No work items found in description: "{description}"', file=sys.stderr)
            sys.exit(0)

        print(f'Work items found: {work_items}', file=sys.stderr)

        # Validate that work items are valid
        client = Connection(base_url=organization, creds=BasicAuthentication('', token)).clients.get_work_item_tracking_client()
        for e in work_items:
            validate_work_item(e, client)
    
        if not validate_only:
            for e in work_items:
                associate_work_item_to_pull_request(e, client, project, url)

    except:
        if debug:
            import pdb
            import traceback
            traceback.print_exc()
            pdb.post_mortem()
            
        raise

def validate_work_item(id: str, client):
    item = client.get_work_item(id=id)

    # Sanity check
    assert(len(item.fields['System.Title']) > 0)

def associate_work_item_to_pull_request(work_item_id: str, client, project, pull_request_url: str):
    comment = f'[AUTOMATED] Pull request completed: {pull_request_url}'
    
    # Caping at 100 comments for simplicity
    existing_comments = client.get_comments(work_item_id=work_item_id, project=project, top=100)
    
    # Validate that comment isn't already there
    if comment in [e.text for e in existing_comments.comments]:
        print(f'Comment already present on work item: {work_item_id}, skipping', file=sys.stderr)
        return
    
    # Write comment
    client.add_comment(work_item_id=work_item_id, project=project, request={'text': comment})
    
    # Add link to PR
    request = {
        "op": "add",
        "path": "/relations/-",
        "value": {
          "rel": "Hyperlink",
          "url":  pull_request_url
        }
    }
    
    client.update_work_item(id=work_item_id, document=[request])

def find_work_item_numbers(message: str) -> list:
    items = [e.replace('MSFT#', '') for e in re.findall('MSFT#[0-9]+', message)]
    if len(items) > 1:
        print(f'WARNING: found more than 1 work items items in message: {message}. Items: {items}', file=sys.stderr)

    return items

if __name__ == '__main__':
    main()
