from snyker import Group, APIClient


def main():
    '''
    First, set your SNYK_TOKEN envar with a Group-Scoped Service Account Token. This allows you to run this script
    without needing to specify a group_id like shown below with print(Group().id)
    '''
    group = Group(api_client=APIClient(
        max_retries=15,  # Number of retries when hitting rate limits
        backoff_factor=0.5,  # Backoff factor for retries
        logging_level=20))  # 10 = DEBUG, 20 = INFO, 30 = WARNING, 40 = ERROR, 50 = CRITICAL

    '''
    Every object with an API associated with it will either have an APIClient object built for them with default values,
    inherited one from a parent caller object or can be explicitly provided one.

    The APIClient object is responsible for making the API calls and handling rate limits as well as logging events
    at multiple levels. Next to be supported is multithreading and async calls.
    '''

    group.get_orgs()
    issues = []
    for org in group.orgs:
        org.get_projects()
        for project in org.projects:
            issues += project.get_issues()
    print(len(issues))

    '''
    Example showing how to get all organizations in a group. Calling a get_ method on objects will both return the 
    list of objects as well set the objects attribute on the object itself.
    '''
    orgs = group.get_orgs()
    if orgs == group.orgs:
        print(f"Matching sets of orgs. Total Orgs: {len(orgs)}, Total Orgs in Group: {len(group.orgs)}")

    '''
    Example showing how to get issues based on parameters provided. See the following link for all supported parameters:
    https://apidocs.snyk.io/#get-/groups/-group_id-/issues
    '''

    group.issues = group.get_issues(
        params={
            "type": "code",  # Type of project in Snyk
            "status": "resolved",  # Status filter of the issues to return
            "ignored": False  # Filter to include ignored issues
        })
    group.issues = group.get_issues(
        params=dict(
            type="code",
            status="resolved",
            ignored=False
        ))

    '''
    Example in accessing a sub-entity like Assets, we can get all assets in a group which are returned as a list of 
    Asset objects. The Query syntax is flexible and can be found from the user documentation:
    https://snyk.gitbook.io/snyk-assets-api/pe1zWq10I0UHWrRJeF8a 
    
    The query object is a dictionary object that can be used to filter the assets returned - in this case,
    we are looking for all assets of type repository and where 'juice-shop' matches on a substring of the name.
    
    If you want to follow along, either modify the name in the query or import the OWASP Juice Shop project into your
    Snyk account from https://github.com/juice-shop/juice-shop though it may take a few hours before the Asset Inventory
    will be able to return it via API.
    
    Notice how the Query object has a 'type' filter. This is because Assets returned are not all of the same type. 
    The API returns a list of Asset objects which can be 'repository', 'image', or <package_manager_name>.
    See the following document to understand what <package_manager_name> is supported: 
    https://docs.snyk.io/snyk-api/api-endpoints-index-and-tips/project-type-responses-from-the-api
    
    '''
    test_query = {
        "query": {
            "attributes": {
                "operator": "and",
                "values": [
                    {
                        "attribute": "type",
                        "operator": "equal",
                        "values": ["repository"]
                    },
                    {
                        "attribute": "name",
                        "operator": "contains",
                        "values": ["juice-shop"]
                    }
                ]
            }
        }
    }
    assets = group.get_assets(query=test_query)

    '''
    Returned objects also have a raw attribute which contains the raw JSON data returned from the API. This is useful 
    for debugging and understanding the data schema returned.
    '''
    import json
    print(json.dumps(assets[0].raw, indent=4))
    '''
    Nice new extension to the Assets API allows the user a quick way to get the projects (from which Issue objects can
    be created) as well as which Organizations an Asset receives project data from. These related entities must
    be called explicitly and are not returned by default. This is because the API can return a large number of items
    and we want to avoid overwhelming the user with data.
    '''
    if len(assets) > 0:
        for asset in assets:
            asset.get_projects()
            asset.get_orgs()

    '''
    Some entities are able to call a singular get_ for the object. For example, the Group object has a get_asset()
    method after being provided an asset_id. This will return a single Asset object that is NOT set in the class.
    '''
    asset = group.get_asset(assets[0].id)  # get_asset by Asset object's .id
    print(json.dumps(asset.raw, indent=4))  # Print the raw asset data
    # asset = group.get_asset('<your_asset_id>')           # get_asset by string

    #  Ask user to press enter to exit, then exit when they do
    print("Press Enter to exit...")
    input()
    group.api_client.close()
    exit(0)


if __name__ == "__main__":
    main()
