from snyker import Group, APIClient
import json


def main():
    """
    Example of how to use the Snyk API client to get all issues in a group and print them. Doubles as a test case.
    """

    '''
    First, set your SNYK_TOKEN envar with a Group-Scoped Service Account Token. This allows you to run this script
    without needing to specify a group_id: Group() 
    
    Every class in snyker with an API associated with it will either have an APIClient object built for them with 
    default values, inherits it from a parent caller object or can be explicitly provided with a new one.

    The APIClient class is responsible for making the API calls and handling rate limits, queueing, as well as 
    logging configuration.

    '''
    group = Group(
        api_client=APIClient(
            max_retries=15,  # Number of retries when hitting rate limits
            backoff_factor=0.5,  # Backoff factor for retries
            logging_level=20))  # 10 = DEBUG, 20 = INFO, 30 = WARNING, 40 = ERROR, 50 = CRITICAL

    '''
    Example showing how to get all organizations in a group then getting the projects and then getting the issues. 
    Calling a get_ method on objects will both return the list of objects as well set the objects attribute on 
    the object itself. It will not 'hydrate' those entities upstream, i.e. group.issues is still unpopulated. This
    may be an upcoming enhancement to the SDK but was deemed low-priority at the moment so we would need to explicitly
    assign the list upstream.
    '''
    import json # This import is redundant, json is already imported at the top
    for org in group.get_orgs(params={'slug': 'cli-upload-test-5jMFX8GCf5RQhAiH5K9fNs'}):
        for proj in org.get_projects(params={'origins': 'cli'}):
            print(json.dumps(proj.raw['data'], indent=4))

    # Initialize group.issues if it might not have been initialized as a list in Group.__init__
    # Based on current Group.__init__, self.issues: List[Issue] = [] so it is initialized.
    # if group.issues is None: # This check should not be necessary
    #    group.issues = []

    for org in group.orgs:
        org.get_projects() # Populates org.projects
        if org.projects: # Check if org.projects is not None and not empty before iterating
            for project in org.projects:
                issues_list = project.get_issues() # Populates project.issues
                if issues_list: # Check if issues_list is not None and not empty
                    # group.issues is initialized as [] in Group.__init__
                    group.issues.extend(issues_list)

    # Corrected variable name from 'orgs' to 'group.orgs'
    print(f"Matching sets of orgs. Total Orgs: {len(group.orgs)}, Total Orgs in Group: {len(group.orgs)}")
    '''
    Policy class has some extensibility designed for it, hence the policy.conditions_group attribute is a 
    ConditionsGroup defined within the Policy class file to access the conditions of the policy.
    '''
    policy_finding_ids = []
    if group.orgs: # Ensure group.orgs is not empty before iterating
        for org in group.orgs:
            # org.policies is populated by org.get_policies(). It might be None if get_policies was not called or failed.
            # It's safer to call get_policies() if we expect policies here, or check if org.policies is populated.
            # For now, assuming if org.policies exists, it's iterable.
            if org.policies: 
                for policy in org.policies:
                    if policy.conditions_group and policy.conditions_group.value: # Check if value exists
                        print(f"{policy.conditions_group.field}: {policy.conditions_group.value}, id: {policy.id}")
                        policy_finding_ids.append(policy.conditions_group.value)
    print(f"Policies found with finding ids: {len(policy_finding_ids)}")
    '''
    Example showing how to get issues based on parameters provided. See the following link for all supported parameters:
    https://apidocs.snyk.io/#get-/groups/-group_id-/issues
    '''

    # This will overwrite group.issues collected from projects earlier.
    # If the intent is to add to them, the logic should be different.
    # For now, assume overwrite is fine as per original script.
    group.issues = group.get_issues(
        params=dict(
            type="code",
            ignored=True
        ))

    issue_finding_ids = []
    if group.issues: # Check if group.issues is not None and not empty
        for issue in group.issues:
            if hasattr(issue, 'key_asset') and issue.key_asset is not None:
                issue_finding_ids.append(issue.key_asset)
                print(f"key_asset: {issue.key_asset}, id: {issue.id}")

    print(f"Issues with key_asset: {len(issue_finding_ids)}")

    diff_1 = list(set(issue_finding_ids) - set(policy_finding_ids))
    diff_2 = list(set(policy_finding_ids) - set(issue_finding_ids))
    print(f"{len(diff_1)} Finding IDs in issues but not in policies: {diff_1}")
    print(f"{len(diff_2)} Finding IDs in policies but not in issues: {diff_2}")

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
    # import json # Redundant
    if assets and len(assets) > 0: # Check if assets list is not empty
        print(json.dumps(assets[0].raw, indent=4))
    else:
        print("No assets found matching the query for 'juice-shop'.")
    '''
    Nice new extension to the Assets API allows the user a quick way to get the projects (from which Issue objects can
    be created) as well as which Organizations an Asset receives project data from. These related entities must
    be called explicitly and are not returned by default. This is because the API can return a large number of items
    and we want to avoid overwhelming the user with data.
    '''
    if assets and len(assets) > 0:
        for asset in assets:
            asset.get_projects()
            asset.get_orgs()

    '''
    Some entities are able to call a singular get_ for the object. For example, the Group object has a get_asset()
    method after being provided an asset_id. This will return a single Asset object that is NOT set in the class.
    '''
    if assets and len(assets) > 0: # Ensure assets list is not empty before accessing assets[0]
        asset_by_obj_id = group.get_asset(assets[0].id)  # get_asset by Asset object's .id
        if asset_by_obj_id:
            print(f"Fetched asset by object ID: {asset_by_obj_id.name}")
    
    asset_by_str_id = group.get_asset('1189c6ce067aa3a5e1896bedaab6614b')  # get_asset by string
    if asset_by_str_id:
        print(f"Fetched asset by string ID: {asset_by_str_id.name}")


    group.api_client.close()
    return


if __name__ == "__main__":
    main()
    print("""
+++++++++++++++++++=----=*##***************************=:......:::.....::-::...::-=+*##########################################
+++++++++++++++++++=----=*##**************************+=::....::::......::::....:--=+**########################################
+++++++++++++++++++=----=*###*******************+====++++***####*=:.....:-::....:=--=--=*######################################
+++++++++++++++++++=----=*###*****************+==--=*#%%%%%%@@@%@@%%#-..:--:...:=======-==*********#*##########################
+++++++++++++++++++=----=*###****+--+***=--=*+=--=*##%#%%%%@@@@@@%@%%%%#*=-:.----++===--=-=*****************#**##*####**######*
+++++++++++++++++++=----=*#*****+=-=++===-==*+=+*#%#%%%@@@@@@@@@@@@@@%%%%%#+:-+=-===++==----+******************************###*
++++++++++++++++++++=---=+*##**+===++=--==+%**%%%%@@@@@@@@@@@@@@@@@@@@%%%%%%#+:=++=--==+==--=+*********************************
+++++++++++++++++++=-:::-=*#**++=++=--==+#=---+@@@@@@@@@@@@@@@@@@@@@@@%@@%##%##*:.=+=---=++-==+********************************
+++++++++++++++++++=-:..:=*#*+====---=++=---=+%@@@@@@@@@@@@@@@@@@@@@@@%@@@%%%%%##-::++=--=++==+********************************
+++++++++++++++++++=-...:=+*++===--=++=---=+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@%%%%-:--++=-==+==********************************
+++++++++++++++++++=-:.:-=*++===-=++=---=+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%#-:-==+=-====+*******************************
+++++++++++++++++++=-:::-+++==--++=---==#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-:-=-=--=++=-=====*******************************
+++++++++++++++++++=-:::=++===-++==--+*@@@@@@@@@%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@#==-----==+==-=====******************************
+++++++++++++++++++=-:::=====-+==--==+@@@#*=--=%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@%#+==--=====-=====*****************************
+++++++++++++++++++=-:::====-+==--==+@%*=-----*%%%####%%%%@@@@@@@@@@@@@@@@@@@@@@@@%@#+=============****************************
+++++++++++++++++++=-::========--==*+=----==*%%%%%#******###%%@%%@@@@@@@@@@@@@@@@@@@@*=*==-=========***************************
+++++++++++++++++++=-:=======---======---+%@@%@%%%##*+****+*##%%%%%%@@@@%%%%%%@@@@@@@%+*+=---========**************************
+++++++++++++++++++=--======--====----=+%@@@@@@%%#***+++++====+*###%%##%#****##%@@@@@@*+++=--=======--*************************
+++++++++++++++++++============-----==#@@@@@@%%##****#*+++==+=+--+=++*****###**#%@@@@@##%#*=--=---=-=--************************
++++++++++++++++++++=========------=%@@@@@@@%%**********#***+++=-+++***###***+**%@@@@@#*%%*=----=--=====***********************
+++++++++++++++++++==+=====-=----==%@@@@@@@%#*****+++*+=====++++==++==++++++****#@@@@@#**##+=----=--===+=+*********************
++++++++++++++++++======--------=*%@@@@@@@@#*****++++*##%##*++++==+++***####*****%@@@%*****+==--------=-:-+********************
+++++++++++++++++=+====---------=%@@@@@@@@%#**+**++++=====++=+++==+*++++===++*+**%@@@+******+==----------::=*******************
++++++++++++++++=====----------=+*@@@@@@@@%#****++++=========+++==++++======++++*%@@%+*******=====--------=--+***************#*
++++++++++++++======----------=+++%@@@@@@@%#*++++++=========+=++==+++++=======++*#@@*=********+====-------==---**********#####*
++++++++++++======----------==+*++*@@%@%@%%**++++===---======++====+++========+++#@%++***********++=-------===--+********######
++++++++++======-----------==+***++#@%%%%%#***+++===----====+++=---=++*=======+++##-=+*************+=---------=---********#####
+++++++++======---------===++***++++%#%%%##***++++===-----=++=======++++=====+++**=-=+*************++=--------=----+#######*###
++++++++======--------===++*****++++*##%%*****+++++=====-=+=+*##+++*##++=====+++*--:-+***************+=--------------+--=-=+###
++=:-+=======-------==++-=******+++==####******++++++============++=++++====++++++::-+***************++==--------=---+#*--=--+*
++-++*=====--------==+-:-=*******++=-=%#++*****+++++================++++++++++++++.:-=****************+====-------=-=+*#+==-=#*
+++==++===--------==+=:--=*******++=--%@#*##****++=+===========+===+++++++++++++:...:=+****************+====-------===--:=-=-=*
=-====++==------==++=-:::=+*****+++=--*@@@@#***+++=+=========+********++++++++++:...:-=****************+====-==---==--::---==-=
-====++++=----===+++=-:.:-=******+==-:-%@@#*****++=========++*#*******++++++++++-:...:-+***************++====++======----=---=-
===-=+++========++++=:...:=******+==--::---+*****+++========+++*++++*+++++++++##+:::..:=+****************=====+=======-------==
=-==-=++====++++++=+=:...:=******++=--::::--+*****+++==+=======++**++=+++++++#%#*+--:..:-==++=======---==========++===------===
=====--===++++++===+=-:.:-=******++==--=++===+++***++++++===++===++=++++=+++*%%#*++=:....-=-=----=-:::--========+=+====-=====-=
==----=++==++++*++++=-:::-+***++++=--+=++====-+++**+++++++======----=====+++#%%#*+++-::-+==+==-=-=--=+++*+=======++++======--==
=--======+++++++-=++=------*+=+==--=+#++=-=====-++++++++++====-------==++++*#%#**++=---==++++==-++==*++*===---======+====-----=
-=======++=+++=++=----======-=*++++==*++=========-=+*+++++++==========+++++*#%#*+++=-==++++++===++=+***+++==----===========----
=--===+++==++===*==--==++++++=+*++*+=-=+=======+==+=+****+++++++++++++++++*****+++==-====+**====+*=**++++*+===-=-===========---
=========+++===+#+===---==++++==++*++---+===-==+++===*#***++*++++++++++**+*=**+*++===++==+++-===+*=*+++++=+==-==-=============-
========+++====+#+==+++===++++====+*++--======-===+===+#***++++++++++++++--*+++++===+*+++=+=--===++*=+==++++===-=-=====+=====--
=======++++====+%+=====+=+=+++====++*++--=-====--====+++*+++++++++==-::.::++++========:-+=+=--====**+==+++=++==========+====---
==++=+++++=====+%*==+=++===+++======++==--=--=======-+=:...............::--=--=-======:-+====-====+*+=++==+++===========++=====
====+==++++=+==+#*+=======++*+==========--==---======++=:.................===----=-==-:============#+====+======+==============
    """)
