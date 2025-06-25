import unittest
import os
import logging

from snyker import (
    GroupPydanticModel,
    OrganizationPydanticModel,
    PolicyPydanticModel,
    APIClient,
)
from snyker.config import API_CONFIG

# Provided IDs
TEST_GROUP_ID = "9365faba-3e72-4fda-9974-267779137aa6"


@unittest.skipIf(
    not os.getenv("SNYK_TOKEN"), "SNYK_TOKEN not set, skipping integration tests"
)
class TestPolicyPydanticModelIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api_client = APIClient(logging_level=logging.DEBUG)
        API_CONFIG["loading_strategy"] = "lazy"  # Ensure lazy for setup

        try:
            group = GroupPydanticModel.get_instance(
                api_client=cls.api_client, group_id=TEST_GROUP_ID
            )
        except ValueError as e:
            raise unittest.SkipTest(
                f"Could not get group instance {TEST_GROUP_ID}: {e}"
            )

        if not group:
            raise unittest.SkipTest(
                f"Group instance {TEST_GROUP_ID} is None after get_instance call."
            )

        cls.org_to_test = None
        if group:
            orgs = group.organizations
            for org_instance in orgs:
                if org_instance.id == "8c12aada-dec1-4670-a39e-60fc1ec59e55":  # Team G
                    cls.org_to_test = org_instance
                    break

        if not cls.org_to_test:
            raise unittest.SkipTest(
                f"Organization 'Team G' not found in Group {TEST_GROUP_ID}."
            )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "api_client") and cls.api_client:
            cls.api_client.close()

    def test_fetch_policies(self):
        """Test fetching policies for the test org."""
        if not self.org_to_test:
            self.skipTest("Organization to test was not loaded in setUpClass.")

        policies = self.org_to_test.fetch_policies()
        self.assertIsNotNone(policies)
        self.assertIsInstance(policies, list)

        if policies:
            self.assertIsInstance(policies[0], PolicyPydanticModel)
            self.api_client.logger.info(
                f"Fetched {len(policies)} policies for org {self.org_to_test.id}. First policy ID: {policies[0].id}, Name: {policies[0].name}"
            )
        else:
            self.api_client.logger.info(
                f"No policies returned for org {self.org_to_test.id}."
            )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s-%(levelname)s-%(name)s - %(message)s"
    )
    unittest.main()
