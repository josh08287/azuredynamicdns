import azure.functions as func
import azure.mgmt.dns
import azure.identity
import logging
import os

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

subscription_id = os.getenv('SUBSCRIPTION_ID')
resource_group = os.getenv('RESOURCE_GROUP_NAME')

@app.route(route="http_trigger")
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Received request for update.')
    hostname = req.params.get('hostname')
    
    new_ip = req.params.get('new_ip')
    if not hostname or not new_ip:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            if not hostname:
                hostname = req_body.get('hostname')
            if not new_ip:
                new_ip = req_body.get('new_ip')
    if not new_ip:
        forwarded_for = req.headers.get('x-forwarded-for')
    hostname = hostname.split('.')[0]
    if hostname and new_ip:
        #
        update_hostname_to_new_ip(hostname,new_ip)
        return func.HttpResponse(f"Updated {hostname} A record to point to {new_ip} successfully.")
    else:
        return func.HttpResponse(f"No hostname provided", status_code=401)
    

def update_hostname_to_new_ip(hostname,newip) -> bool:
    #first check if that host already exists in the zone:
    if os.getenv('AZURE_EXTENSION_DIR') is None:
        cred = azure.identity.InteractiveBrowserCredential()
        #token = cred.get_token()
    else:
        cred = azure.identity.ManagedIdentityCredential()
    client = azure.mgmt.dns.DnsManagementClient(cred,subscription_id)
    
    client.record_sets.create_or_update(resource_group_name=resource_group,zone_name='joshuablaine.net',relative_record_set_name=hostname,record_type="A",
                                        parameters={"ttl":300,"arecords":[{"ipv4_address":newip}]})
    for rs in client.record_sets.list_by_dns_zone(resource_group,'joshuablaine.net'):
        print(rs)
    return False