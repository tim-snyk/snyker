from snyker import GroupPydanticModel, APIClient
import os
import json

def main():
    snyk_token = os.getenv("SNYK_TOKEN")
    if not snyk_token:
        print("Error: SNYK_TOKEN environment variable not set.")
        return

    api_client = APIClient()
    try:
        group = GroupPydanticModel.get_instance(api_client=api_client, group_id="9365faba-3e72-4fda-9974-267779137aa6")
        org = next((o for o in group.organizations if o.name == "Team G"), None)
        if org:
            project = next((p for p in org.projects if p.name == "cpp-goof"), None)
            if project:
                print(f"Found project 'cpp-goof' in organization {org.name}")
                response = project._api_client.get(f"/rest/orgs/{org.id}/projects/{project.id}/issues?version=2024-10-15")
                print(json.dumps(response.json(), indent=2))
            else:
                print("Project 'cpp-goof' not found in organization.")
        else:
            print("Organization 'Team G' not found.")
    finally:
        api_client.close()

if __name__ == "__main__":
    main()
