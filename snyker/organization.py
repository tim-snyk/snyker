from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from .group import Group
    from .api_client import APIClient  # APIClient is usually passed or accessed via group
    from .project import Project
    from .issue import Issue
    from .policy import Policy
import os
from snyker.project import Project
import concurrent.futures

token = os.getenv('SNYK_TOKEN')  # Set your API token as an environment variable
api_version = "2024-10-15"  # Set the API version.


class Organization:
    def __init__(self,
                 org_id: str,
                 group: Optional['Group'] = None,
                 api_client: Optional['APIClient'] = None,
                 params: dict = {}):
        try:
            self.id = org_id
            self.group = Group() if group is None else group
            self.api_client = self.group.api_client if api_client is None else api_client
            self.logger = self.api_client.logger
            self.raw = self.get_org(params=params) # Fetch organization data
            self.integrations = None
            self.projects: Optional[List[Project]] = None
            self.issues: Optional[List[Issue]] = None
            self.policies: Optional[List[Policy]] = None

            # Attribute helpers
            self.group_id = self.group.id
            self.name = self.raw['data']['attributes']['name']
            self.slug = self.raw['data']['attributes']['slug']

        except KeyError as e:
            self.api_client.logger.error(f"KeyError: {e} in organization data: {self.raw}")
            raise
        except Exception as e:
            self.api_client.logger.error(f"Unexpected error: {e} in organization data: {self.raw}")
            raise
        self.logger.debug(f"[Org ID: {self.id}].__init__ created organization object for {self.name} ")

    def get_org(self, params: dict = {}) -> dict:
        '''
        # GET /rest/orgs/{orgId}?version={api_version}
        '''
        uri = f"/rest/orgs/{self.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{token}'
        }
        params = {
            'version': api_version,
        }
        params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        return response.json()

    def get_issues(self, params: dict = {}) -> list[Issue]:
        '''
        # GET /rest/orgs/{orgId}/issues
        '''
        from snyker import Issue
        uri = f"/rest/orgs/{self.id}/issues"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100,
        }
        current_params.update(params)
        data_items = []
        self.logger.debug(f"[Org: {self.id}].get_issues Starting to fetch all issue data items for concurrent "
                          f"processing using params: {current_params}")
        # Use the APIClient's paginate method to fetch all issue data
        try:
            for data_item in self.api_client.paginate(
                    endpoint=uri,
                    params=current_params,
                    data_key='data',  # Snyk API typically returns items in 'data' list
                    headers=headers
            ):
                data_items.append(data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Org: {self.id}].get_issues Error during pagination for issues: {e_paginate}",
                              exc_info=True)
            self.issues = []
            return []
        self.logger.debug(f"[Org: {self.id}].get_issues Collected {len(data_items)} issue data items.")
        if not data_items:
            self.logger.debug(f"[Org: {self.id}].get_issues No issue data items found to process with current filters.")
            self.issues = []
            return []
        issue_futures = []
        self.logger.debug(
            f"[Org: {self.id}].get_issues passing {len(data_items)} Issue instantiations to executor.")
        for issue_data in data_items:
            future = self.api_client.submit_task(
                Issue,  # The Issue class constructor
                issue_data=issue_data,  # The raw data for one issue
                group=self  # Passing the Organization instance as 'group'
            )
            issue_futures.append(future)
        issues_results: List[Issue] = []
        self.logger.debug(
            f"[Org: {self.id}].get_issues Waiting for {len(issue_futures)} Issue instantiations to complete.")
        for i, future in enumerate(concurrent.futures.as_completed(issue_futures)):
            try:
                issue_instance = future.result()
                if issue_instance:  # Ensure result is not None
                    issues_results.append(issue_instance)
                log_identifier = getattr(issue_instance, 'id', 'N/A') if issue_instance else 'None'
                self.logger.debug(
                    f"[Org: {self.id}].get_issues Completed issue instantiation {i + 1}/{len(issue_futures)}: "
                    f"Issue ID/Ref '{log_identifier}'")
            except Exception as e_future:
                self.logger.error(
                    f"[Org: {self.id}].get_issues Error instantiating an issue concurrently (task {i + 1}): {e_future}",
                    exc_info=True)
        self.issues = issues_results
        self.logger.info(
            f"[Org: {self.id}].get_issues successfully instantiated {len(self.issues)} of "
            f"{len(data_items)} Issues with params: {dict(params)}")  # Log original user params
        return self.issues

    def get_policies(self, params: dict = {}) -> list[Policy]:
        '''
        # GET /rest/orgs/{orgId}/policies
        '''
        from snyker import Policy
        uri = f"/rest/orgs/{self.id}/policies"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100,
        }
        current_params.update(params)
        data_items = []
        self.logger.debug(f"[Org: {self.id}].get_policies Starting to fetch all issue data items for concurrent "
                          f"processing using params: {current_params}")
        # Use the APIClient's paginate method to fetch all issue data
        try:
            for data_item in self.api_client.paginate(
                    endpoint=uri,
                    params=current_params,
                    data_key='data',  # Snyk API typically returns items in 'data' list
                    headers=headers
            ):
                data_items.append(data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Org: {self.id}].get_policies Error during pagination for issues: {e_paginate}",
                              exc_info=True)
            return []
        self.logger.debug(f"[Org: {self.id}].get_policies Collected {len(data_items)} issue data items.")
        if not data_items:
            self.logger.debug(
                f"[Org: {self.id}].get_policies No policy data items found to process with current filters.")
            return []
        policy_futures = []
        self.logger.debug(
            f"[Org: {self.id}].get_policies passing {len(data_items)} Issue instantiations to executor.")
        for policy_data in data_items:
            future = self.api_client.submit_task(
                Policy,  # The Policy class constructor
                policy_data=policy_data,  # The raw data for one policy
                org=self  # Passing the Organization instance as
            )
            policy_futures.append(future)
        policy_results: List[Policy] = []
        self.logger.debug(
            f"[Org: {self.id}].get_policies Waiting for {len(policy_futures)} Issue instantiations to complete.")
        for i, future in enumerate(concurrent.futures.as_completed(policy_futures)):
            try:
                policy_instance = future.result()
                if policy_instance:  # Ensure result is not None
                    policy_results.append(policy_instance)
                log_identifier = getattr(policy_instance, 'id', 'N/A') if policy_instance else 'None'
                self.logger.debug(
                    f"[Org: {self.id}].get_policies Completed issue instantiation {i + 1}/{len(policy_futures)}: "
                    f"Policy ID/Ref '{log_identifier}'")
            except Exception as e_future:
                self.logger.error(
                    f"[Org: {self.id}].get_policies Error instantiating a policy concurrently (task {i + 1}): {e_future}",
                    exc_info=True)
        self.policies = policy_results
        self.logger.info(
            f"[Org: {self.id}].get_policies successfully instantiated {len(self.policies)} of "
            f"{len(data_items)} Policies with params: {dict(params)}")  # Log original user params
        return self.policies

    def get_integrations(self) -> List[dict]:
        '''
        # GET https://api.snyk.io/v1/org/{orgId}/integrations
        '''
        uri = f"/v1/org/{self.id}/integrations"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {token}'
        }
        all_integrations_data_items = []
        try:
            for integrations_data_item in self.api_client.paginate(
                    endpoint=uri,
                    headers=headers
            ):
                all_integrations_data_items.append(integrations_data_item)
        except Exception as e_paginate:
            self.logger.error(
                f"[Org: {self.id}].get_integrations Error during pagination for integrations: {e_paginate}",
                exc_info=True)
            self.integrations = []
            return []
        self.logger.debug(f"[Org: {self.id}].get_integrations Collected {len(all_integrations_data_items)} "
                          f"integrations data items.")
        if not all_integrations_data_items:
            self.logger.debug(f"[Org: {self.id}].get_integrations No integrations data items found to process.")
            self.integrations = []
            return []
        integrations = []

        ##############
        self.integrations = all_integrations_data_items
        return self.integrations
        #############
        self.logger.debug(
            f"[Org: {self.id}].get_integrations passing {len(all_integrations_data_items)} Integration data items to executor.")
        for integrations_data in all_integrations_data_items:
            # Submit Integration instantiation to the executor
            # Integration.__init__ will make its own API call (self.get_integration)
            future = self.api_client.submit_task(
                dict,  # The Integration class constructor
                integration_data=integrations_data,  # The raw data for one integration
                group=self  # Passing the Organization instance as 'group'
            )
            integrations.append(future)
        integrations_results: List[dict] = []
        self.logger.debug(
            f"[Org: {self.id}].get_integrations Waiting for {len(integrations)} Integration instantiations to complete.")
        for i, future in enumerate(concurrent.futures.as_completed(integrations)):
            try:
                integration_instance = future.result()
                if integration_instance:  # Ensure result is not None
                    integrations_results.append(integration_instance)
                log_identifier = getattr(integration_instance, 'id', 'N/A') if integration_instance else 'None'
                self.logger.debug(
                    f"[Org: {self.id}].get_integrations Completed integration instantiation {i + 1}/{len(integrations)}: "
                    f"Integration ID/Ref '{log_identifier}'")
            except Exception as e_future:
                self.logger.error(
                    f"[Org: {self.id}].get_integrations Error instantiating an integration concurrently (task {i + 1}): {e_future}",
                    exc_info=True)
        self.integrations = integrations_results

        self.integrations = integrations
        return integrations

    def get_projects(self, params: dict = {}) -> List['Projects']:
        '''
        # GET /rest/orgs/{orgId}/projects?version={api_version}
        '''
        from snyker.project import Project
        uri = f"/rest/orgs/{self.id}/projects"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        current_params = {
            'version': api_version,
            'limit': 100,
        }
        current_params.update(params)
        all_project_data_items = []
        self.logger.debug(f"[Org: {self.id}].get_projects Starting to fetch all project data items for concurrent"
                          f" processing.")
        # Use the APIClient's paginate method to fetch all project data
        try:
            for project_data_item in self.api_client.paginate(
                    endpoint=uri,
                    params=current_params,
                    data_key='data',  # Snyk API typically returns items in 'data' list
                    headers=headers
            ):
                all_project_data_items.append(project_data_item)
        except Exception as e_paginate:
            self.logger.error(f"[Org: {self.id}].get_projects Error during pagination for projects: "
                              f"{e_paginate}", exc_info=True)
            # Depending on desired behavior, either return empty or raise
            self.projects = []
            return []
        self.logger.debug(f"[Org: {self.id}].get_projects Collected {len(all_project_data_items)} project data items.")
        if not all_project_data_items:
            self.logger.debug(f"[Org: {self.id}].get_projects No project data items found to process.")
            self.projects = []
            return []
        project_futures = []
        self.logger.debug(
            f"[Org: {self.id}].get_projects passing {len(all_project_data_items)} Project instantiations to executor.")
        for project_data in all_project_data_items:
            project_id = project_data.get('id')
            if not project_id:
                self.logger.warning(
                    f"[Org: {self.id}] Found project data item without an ID: {project_data}. Skipping.")
                continue

            # Submit Project instantiation to the executor
            # Project.__init__ will make its own API call (self.get_project)
            future = self.api_client.submit_task(
                Project,  # The Project class constructor
                project_id=project_id,
                organization=self,  # Pass the current Organization instance
                group=self.group,  # Pass the group associated with this organization
                api_client=self.api_client  # Project constructor can get it from group or explicitly
            )
            project_futures.append(future)

        projects_results: List[Project] = []
        self.logger.info(f"[Org: {self.id}].get_projects Waiting for {len(project_futures)}"
                         f" Project instantiations to complete.")
        for i, future in enumerate(concurrent.futures.as_completed(project_futures)):
            try:
                project_instance = future.result()
                if project_instance:  # Ensure result is not None
                    projects_results.append(project_instance)
                self.logger.debug(
                    f"[Org: {self.id}].get_projects Completed project instantiation {i + 1}/{len(project_futures)}:"
                    f" {project_instance.name if project_instance else 'None'}")
            except Exception as e_future:
                self.logger.error(
                    f"[Org: {self.id}].get_projects Error instantiating a project concurrently (task {i + 1}):"
                    f" {e_future}",
                    exc_info=True)
                # Optionally, collect failed instantiations or handle errors
        self.projects = projects_results
        self.logger.info(
            f"[Org: {self.id}].get_projects successfully instantiated {len(self.projects)} of "
            f"{len(all_project_data_items)} Projects.")
        return self.projects

    def get_project(self, project_id: str, params: dict = {}):
        '''
        # GET /rest/orgs/{orgId}/projects/{projectId}?version={api_version}
        '''
        from snyker import Project
        uri = f"/rest/orgs/{self.id}/projects/{project_id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_client.token}'
        }
        params = {
            'version': api_version,
        }
        params.update(params)
        response = self.api_client.get(
            uri,
            headers=headers,
            params=params
        )
        return Project(response.json()['data'], self)