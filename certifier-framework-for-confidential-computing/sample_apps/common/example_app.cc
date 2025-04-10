//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <fstream>      // For std::ifstream and std::ofstream
#include <stdexcept>    // For std::exception
#include <cstdlib>      // For system()
#include <string>
#include <exception>

#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "certifier_algorithms.h"

// #include "bioinformatics.pb.h"
// #include <google/protobuf/text_format.h>

using namespace certifier::framework;
using namespace certifier::utilities;
// using certifier::bioinformatics::BioinformaticsRequest;
// using certifier::bioinformatics::BioinformaticsResponse;

// Ops are: cold-init, get-certified, run-app-as-client, run-app-as-server
DEFINE_bool(print_all, false, "verbose");
DEFINE_string(operation, "", "operation");

DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");
DEFINE_string(data_dir, "./app1_data/", "directory for application data");

DEFINE_string(server_app_host, "localhost", "address for app server");
DEFINE_int32(server_app_port, 8124, "port for server app server");

DEFINE_string(policy_store_file, "store.bin", "policy store file name");

#ifdef SIMPLE_APP
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");

DEFINE_string(public_key_alg, Enc_method_rsa_2048, "public key algorithm");
DEFINE_string(auth_symmetric_key_alg,
              Enc_method_aes_256_cbc_hmac_sha256,
              "authenticated symmetric key algorithm");

DEFINE_string(analysis_type, "sequence_quality", "Type of analysis to perform");
DEFINE_string(repository_url, "", "URL of data repository");
DEFINE_string(dataset_name, "example.fastq", "Name of dataset to analyze");
DEFINE_string(parameters, "--quiet --threads 2", "Analysis parameters");

static string enclave_type("simulated-enclave");

// Helper function to read file contents
std::string read_file_contents(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), 
                      std::istreambuf_iterator<char>());
}

bool perform_bioinformatics_analysis(const string& analysis_type,
                                   const string& input_file,
                                   const string& parameters,
                                   string* result_output,
                                   string* error_msg) {
    try {
        // Create unique temp directory for results
        string work_dir = "/tmp/bio_fasta";
        mkdir(work_dir.c_str(), 0777);
        
        string command;
        if (analysis_type == "sequence_quality") {
            command = "fastqc " + input_file + " " + parameters + " -o " + work_dir + " 2>&1";
        } else {
            *error_msg = "Unsupported analysis type: " + analysis_type;
            return false;
        }

        printf("Executing: %s\n", command.c_str());
        
        // Execute and show real-time output
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            *error_msg = "Failed to execute analysis command";
            return false;
        }

        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            printf("%s", buffer);  // Print output in real-time
        }
        
        int ret = pclose(pipe);
        if (ret != 0) {
            *error_msg = "Analysis failed with exit code " + std::to_string(ret);
            return false;
        }

        // Get results file path
        string output_file = work_dir + "/" + 
                          input_file.substr(input_file.find_last_of("/\\") + 1) + 
                          "_fastqc.html";
                          
        *result_output = read_file_contents(output_file);
        // if (result_output->empty()) {
        //     *error_msg = "No results generated in " + output_file;
        //     return false;
        // }

        printf("\nResults saved to: %s\n", output_file.c_str());
        return true;
    } catch (const std::exception& e) {
        *error_msg = string("Exception: ") + e.what();
        return false;
    }
}


// Parameters for simulated enclave
bool get_enclave_parameters(string **s, int *n) {

  // serialized attest key, measurement, serialized endorsement, in that order
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_attest_key_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_measurement_file,
                             &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement,
                             &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  *n = 3;
  return true;

err:
  delete[] args;
  *s = nullptr;
  return false;
}
#endif  // SIMPLE_APP

#ifdef GRAMINE_SIMPLE_APP
DEFINE_string(gramine_cert_file, "sgx.cert.der", "certificate file name");

static string enclave_type("gramine-enclave");

// Parameters for gramine enclave
bool get_enclave_parameters(string **s, int *n) {

  string *args = new string[1];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_gramine_cert_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read cert cert file\n",
           __func__,
           __LINE__);
    delete[] args;
    *s = nullptr;
    return false;
  }

  *n = 1;
  return true;
}
#endif  // GRAMINE_SIMPLE_APP

#ifdef SEV_SIMPLE_APP
DEFINE_string(ark_cert_file, "ark_cert.der", "ark cert file name");
DEFINE_string(ask_cert_file, "ask_cert.der", "ask cert file name");
DEFINE_string(vcek_cert_file, "vcek_cert.der", "vcek cert file name");

static string enclave_type("sev-enclave");

// Parameters for sev enclave for now.
// We will switch to using extended guest requests in the future.
bool get_enclave_parameters(string **s, int *n) {

  // ark cert file, ask cert file, vcek cert file
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ark_cert_file, &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ask_cert_file, &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_vcek_cert_file, &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  *n = 3;
  return true;

err:
  delete[] args;
  *s = nullptr;
  return false;
}
#endif  // SEV_SIMPLE_APP

#ifdef ISLET_SIMPLE_APP
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");

static string enclave_type("islet-enclave");

// Parameters not needed for ISLET enclave
bool get_enclave_parameters(string **s, int *n) {
  *s = nullptr;
  *n = 0;
  return true;
}
#endif  // ISLET_SIMPLE_APP

#ifdef KEYSTONE_SIMPLE_APP
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");

static string enclave_type("keystone-enclave");

// Parameters not needed for Keystone enclave
bool get_enclave_parameters(string **s, int *n) {
  *s = nullptr;
  *n = 0;
  return true;
}
#endif  // KEYSTONE_SIMPLE_APP

// The test app performs five possible roles
//    cold-init: This creates application keys and initializes the policy store.
//    get-certified: This obtains the app admission cert naming the public app
//    key from the service. run-app-as-client: This runs the app as a client.
//    run-app-as-server: This runs the app as server.
//    warm-restart:  This retrieves the policy store data. Operation is subsumed
//      under other ops.

#include "policy_key.cc"

cc_trust_manager *trust_mgr = nullptr;

// -----------------------------------------------------------------------------------------

bool client_application(secure_authenticated_channel &channel) {
    printf("Client peer id is %s\n", channel.peer_id_.c_str());

    // Initial handshake with server
    const char *msg = "Hi from your secret client\n";
    channel.write(strlen(msg), (byte *)msg);

    string out;
    channel.read(&out);
    printf("Server response: %s\n", out.data());
    channel.close();  // Close channel after handshake

    printf("\n=== Starting Bioinformatics Analysis ===\n");
    printf("Analysis type: %s\n", FLAGS_analysis_type.c_str());
    printf("Dataset: %s\n", FLAGS_dataset_name.c_str());

    string result;
    string error;
    bool success = false;
    string input_path;

    try {
        // Setup working directory
        string work_dir = "/tmp/bio_fasta";
        
        if (!FLAGS_repository_url.empty()) {
            printf("Cloning repository...\n");
            string cmd = "git clone " + FLAGS_repository_url + " " + work_dir + "/repo 2>&1";
            if (system(cmd.c_str()) != 0) {
                throw std::runtime_error("Git clone failed");
            }
            input_path = work_dir + "/repo/" + FLAGS_dataset_name;
        } else {
            input_path = FLAGS_data_dir + FLAGS_dataset_name;
        }

        // Run analysis
        success = perform_bioinformatics_analysis(
            FLAGS_analysis_type,
            input_path,
            FLAGS_parameters,
            &result,
            &error);

        if (success) {
            printf("\n=== ANALYSIS COMPLETE ===\n");
            printf("First 200 characters of results:\n%.200s...\n", result.c_str());
        } else {
            printf("\n=== ANALYSIS FAILED ===\n%s\n", error.c_str());
        }

    } catch (const std::exception& e) {
        printf("\nERROR: %s\n", e.what());
        success = false;
    }

    // Cleanup
    string cleanup_cmd = "rm -rf /tmp/bio_fasta/repo";
    int cleanup_status = system(cleanup_cmd.c_str());
    if (cleanup_status != 0) {
        printf("Warning: Cleanup command failed (status %d)\n", cleanup_status);
    }

    return success;
}
void server_application(secure_authenticated_channel &channel) {
    printf("Server peer id is %s\n", channel.peer_id_.c_str());
  // Read message from client over authenticated, encrypted channel
  string out;
  int    n = channel.read(&out);
  printf("SSL server read: %s\n", (const char *)out.data());

  // Reply over authenticated, encrypted channel
  const char *msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte *)msg);
//   channel.close();
}


int main(int an, char **av) {
  string usage("Simple App");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  // clang-format off
  if (FLAGS_operation == "") {
    printf("                                                                            (Defaults)\n");
    printf("%s --operation=<op>                                        ; %s", av[0], "(See below)");
    printf("\n\
                  --policy_host=policy-host-address                       ; %s\n\
                  --policy_port=policy-host-port                          ; %d\n\
                  --server_app_host=my-server-host-address                ; %s\n\
                  --server_app_port=my-server-port-number                 ; %d\n\
                  --data_dir=-directory-for-app-data                      ; %s\n\
                  --policy_cert_file=self-signed-policy-cert-file-name    ; \n\
                  --policy_store_file=policy-store-file-name              ; %s\n\
                  --print_all=true|false",
                  FLAGS_policy_host.c_str(),
                  FLAGS_policy_port,
                  FLAGS_server_app_host.c_str(),
                  FLAGS_server_app_port,
                  FLAGS_data_dir.c_str(),
                  FLAGS_policy_store_file.c_str());
#ifdef SIMPLE_APP
    printf("\n\
                  --platform_file_name=platform-cert-bin-file-name        ; %s\n\
                  --platform_attest_endorsement=endorsement-bin-file-name ; %s\n\
                  --measurement_file=measurement-bin-file-name            ; %s\n\
                  --attest_key_file=attest-key-bin-file-name              ; %s\n",
                  FLAGS_platform_file_name.c_str(),
                  FLAGS_platform_attest_endorsement.c_str(),
                  FLAGS_measurement_file.c_str(),
                  FLAGS_attest_key_file.c_str());
#endif  // SIMPLE_APP

#ifdef SEV_SIMPLE_APP
    printf("\n\
                  --ark_cert_file=./service/milan_ark_cert.der \n\
                  --ask_cert_file=./service/milan_ask_cert.der \n\
                  --vcek_cert_file=./service/milan_vcek_cert.der ");
#endif  // SEV_SIMPLE_APP
#ifdef GRAMINE_SIMPLE_APP
    printf("\n\
                  --gramine_cert_file=sgx.cert.der");
#endif  // GRAMINE_SIMPLE_APP
    printf("\n\nOperations are: cold-init, get-certified, "
           "run-app-as-client, run-app-as-server\n");

#ifdef SIMPLE_APP

    // clang-format off
    printf("\nFor the simple_app, you can additionally drive 'cold-init' with different pairs of:\n");
    printf("\n\
    --public_key_alg=public-key-algorigthm-name                          : %s\n\
    --auth_symmetric_key_alg=authenticated-symmetric-key-algorigthm-name : %s\n",
            FLAGS_public_key_alg.c_str(),
            FLAGS_auth_symmetric_key_alg.c_str());
    // clang-format on

    printf("\nPublic-key algorithms supported:\n");
    for (int i = 0; i < Num_public_key_algorithms; i++) {
      printf("  %s\n", Enc_public_key_algorithms[i]);
    }
    printf("\nSymmetric-key algorithms supported:\n");
    for (int i = 0; i < Num_symmetric_key_algorithms; i++) {
      printf("  %s\n", Enc_authenticated_symmetric_key_algorithms[i]);
    }

#endif  // SIMPLE_APP
    return 0;
  }
  // clang-format on

  SSL_library_init();
  string purpose("authentication");

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  trust_mgr = new cc_trust_manager(enclave_type, purpose, store_file);
  if (trust_mgr == nullptr) {
    printf("%s() error, line %d, couldn't initialize trust object\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Init policy key info
  if (!trust_mgr->init_policy_key(initialized_cert, initialized_cert_size)) {
    printf("%s() error, line %d, Can't init policy key\n", __func__, __LINE__);
    return 1;
  }

  // Get parameters
  string *params = nullptr;
  int     n = 0;
  if (!get_enclave_parameters(&params, &n)) {
    printf("%s() error, line %d, get enclave parameters\n", __func__, __LINE__);
    return 1;
  }

  // Init simulated enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init enclave\n", __func__, __LINE__);
    return 1;
  }
  if (params != nullptr) {
    delete[] params;
    params = nullptr;
  }

  // clang-format off

  // Use specified algorithms for the enclave            Defaults:
#ifdef SIMPLE_APP
  // We support --public_key_alg and --auth_symmetric_key_alg only for simple_app
  // (as a way to exercise tests w/ different pairs of algorithms).
  string public_key_alg(FLAGS_public_key_alg);                  // Enc_method_rsa_2048
  string auth_symmetric_key_alg(FLAGS_auth_symmetric_key_alg);  // Enc_method_aes_256_cbc_hmac_sha256
  if (FLAGS_print_all) {
      printf("measurement file='%s', ", FLAGS_measurement_file.c_str());
  }
#else
  string public_key_alg(Enc_method_rsa_2048);
  string auth_symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);
#endif  // SIMPLE_APP

  // clang-format on

  if (FLAGS_print_all && (FLAGS_operation == "cold-init")) {
    printf("public_key_alg='%s', authenticated_symmetric_key_alg='%s\n",
           public_key_alg.c_str(),
           auth_symmetric_key_alg.c_str());
  }

  // Carry out operation
  int ret = 0;
  if (FLAGS_operation == "cold-init") {
    if (!trust_mgr->cold_init(public_key_alg,
                              auth_symmetric_key_alg,
                              "simple-app-home_domain",
                              FLAGS_policy_host,
                              FLAGS_policy_port,
                              FLAGS_server_app_host,
                              FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
#ifdef DEBUG
    trust_mgr->print_trust_data();
#endif  // DEBUG
  } else if (FLAGS_operation == "get-certified") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!trust_mgr->certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
#ifdef DEBUG
    trust_mgr->print_trust_data();
#endif  // DEBUG
  } else if (FLAGS_operation == "run-app-as-client") {
    string                       my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    printf("Running App as client\n");
    if (!trust_mgr->cc_auth_key_initialized_
        || !trust_mgr->cc_policy_info_initialized_) {
      printf("%s() error, line %d, trust data not initialized\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    if (!trust_mgr->primary_admissions_cert_valid_) {
      printf("%s() error, line %d, primary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    if (!channel.init_client_ssl(FLAGS_server_app_host,
                                 FLAGS_server_app_port,
                                 *trust_mgr)) {
      printf("%s() error, line %d, Can't init client app\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    // This is the actual application code.
    if (!client_application(channel)) {
      printf("%s() error, line %d, client_application failed\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "run-app-as-server") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    printf("Running App as server\n");
    if (!server_dispatch(FLAGS_server_app_host,
                         FLAGS_server_app_port,
                         *trust_mgr,
                         server_application)) {
      ret = 1;
      goto done;
    }
  } else {
    printf("%s() error, line %d, Unknown operation\n", __func__, __LINE__);
  }

done:
  // trust_mgr->print_trust_data();
  trust_mgr->clear_sensitive_data();
  if (trust_mgr != nullptr) {
    delete trust_mgr;
  }
  return ret;
}