import os
import unittest
import unittest.mock
import dodevops.dodevops


class TestGetSecretKeyEnvKeyFromEnv(unittest.TestCase):

    def test_valid_env_var(self):
        # Prepare test data
        env_var_list = ["TEST_KEY", "test_key1", "TESTING_KEY"]

        # Set an environment variable for testing purposes
        os.environ["TEST_KEY"] = "my_secret_key"

        # Execute the function
        result = dodevops.dodevops.get_secret_key_env_key_from_env(env_var_list)

        # Assert the result
        self.assertEqual(result, "TEST_KEY")

    def test_invalid_env_var(self):
        # Prepare test data
        env_var_list = ["TEST_KEY_NONE", "test_key1_NONE", "TESTING_KEY_NONE"]

        # Make sure the environment variables are unset
        for var_name in env_var_list:
            os.environ.pop(var_name, None)

        # Execute the function
        result = dodevops.dodevops.get_secret_key_env_key_from_env(env_var_list)

        # Assert the result should be None, as no environment variable is set
        self.assertIsNone(result)

    def test_multiple_valid_env_vars(self):
        # Prepare test data
        env_var_list = ["TEST_KEY", "test_key1", "TESTING_KEY"]

        # Set multiple environment variables for testing purposes
        os.environ["TEST_KEY"] = "my_api_key"
        os.environ["TESTING_KEY"] = "my_secret_key"

        # Execute the function
        result = dodevops.dodevops.get_secret_key_env_key_from_env(env_var_list)

        # Assert the result
        self.assertEqual(result, "TEST_KEY")


class TestGetEnvVarFromListOrKeepOriginal(unittest.TestCase):
    def test_override_true_with_matching_env_var(self):
        env_var_list = ["ENV_VAR1", "ENV_VAR2"]
        with unittest.mock.patch('os.getenv', return_value="VALUE_FROM_ENV_VAR"):
            result = dodevops.dodevops._get_env_var_from_list_or_keep_original(env_var_list)

            os.getenv.assert_called_once_with("ENV_VAR1")
        self.assertEqual(result, "VALUE_FROM_ENV_VAR")

    def test_override_true_with_no_matching_env_var(self):
        env_var_list = ["ENV_VAR1", "ENV_VAR2"]
        with unittest.mock.patch('os.getenv', return_value=None):
            result = dodevops.dodevops._get_env_var_from_list_or_keep_original(env_var_list)

            os.getenv.assert_has_calls([unittest.mock.call("ENV_VAR1"), unittest.mock.call("ENV_VAR2")])

        self.assertIsNone(result)

    def test_override_false_with_original_value(self):
        env_var_list = ["ENV_VAR1", "ENV_VAR2"]
        original_value = "ORIGINAL_VALUE"
        with unittest.mock.patch('os.getenv', return_value="NEW_VALUE"):
            result = dodevops.dodevops._get_env_var_from_list_or_keep_original(env_var_list,
                                                                               original_value=original_value,
                                                                               override=False)
            os.getenv.assert_not_called()
        self.assertEqual(result, original_value)

    def test_override_true_with_original_value(self):
        env_var_list = ["ENV_VAR1", "ENV_VAR2"]
        original_value = "ORIGINAL_VALUE"
        # os.getenv = unittest.mock.Mock(return_value="NEW_VALUE")
        with unittest.mock.patch('os.getenv', return_value="NEW_VALUE"):
            result = dodevops.dodevops._get_env_var_from_list_or_keep_original(env_var_list,
                                                                               original_value=original_value,
                                                                               override=True)
            os.getenv.assert_called_once_with("ENV_VAR1")

        self.assertEqual(result, "NEW_VALUE")


if __name__ == '__main__':
    unittest.main()
