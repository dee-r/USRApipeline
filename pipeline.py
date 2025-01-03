#!/usr/bin/python3

import os
import t2py
from t2py import T2Utils
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

from sklearn.naive_bayes import MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
import xgboost as xgb
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier

from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score, confusion_matrix,
                             ConfusionMatrixDisplay)


# global counter for file naming
i = 0


def call_zeek(inputdirectory, outputdirectory):
    """
    Performs Zeek processing for each file in inputdirectory.
    :param inputdirectory: directory containing pcap files for processing
    :param outputdirectory: directory to place output files in
    """
    global i
    for content in inputdirectory:
        if content.is_file() and content.name.endswith('.pcap'):
            print("Processing {}".format(content.path))
            os.system("zeek -r {} ~/zeekScripts/disable_stream.zeek".format(content.path))
            os.system("mv conn.log {}/conn{}.log".format(outputdirectory, i))
            i += 1


def call_argus(inputdirectory, outputdirectory):
    """
    Performs Argus processing for each file in inputdirectory.
    :param inputdirectory: directory containing pcap files for processing
    :param outputdirectory: directory to place output files in
    """
    global i
    for content in inputdirectory:
        if content.is_file() and content.name.endswith('.pcap'):
            print("Processing {}".format(content.path))
            os.system("argus -r {} -w flows.argus".format(content.path))
            # create CSV from argus file
            os.system("ra -r flows.argus > intermediate.csv")
            # separate fixed-width argus columns into comma separated
            os.system("awk -v OFS=, '{ print substr($0, 4, 15), substr($0, 21, 8), substr($0, 31, 5), "
                      "substr($0, 37, 18), substr($0, 56, 6), substr($0, 65, 3),substr($0, 69, 18), "
                      "substr($0, 88, 6), substr($0, 96, 7), substr($0, 106, 8), substr($0, 115, 5) }' "
                      "intermediate.csv > intermediate2.csv")
            # delete extra spaces from csv
            os.system("tr -d ' ' < intermediate2.csv > intermediate3.csv")
            # move 'State' column values into their proper position
            awk_command = """
            awk -F, '{
                if ($(NF) == "" && $(NF-1) != "") {
                    for (i=1; i<=NF-2; i++) printf("%s,", $i);
                    printf(",%s\\n", $(NF-1));
                } else {
                    print $0;
                }
            }' intermediate3.csv > flows.csv
            """
            os.system(awk_command)

            # move resulting file to the output directory
            os.system("mv flows.csv {}/output{}.csv".format(outputdirectory, i))
            os.system("rm flows.argus intermediate.csv intermediate2.csv intermediate3.csv")

            i += 1


def call_tranalyzer(inputdirectory, outputdirectory):
    """
    Performs Tranalyzer processing for each file in inputdirectory.
    :param inputdirectory: directory containing pcap files for processing
    :param outputdirectory: directory to place output files in
    """
    for content in inputdirectory:
        if content.is_file() and content.name.endswith('.pcap'):
            print("Processing {}".format(content.path))
            T2Utils.run_tranalyzer(pcap=content.path, output_prefix=outputdirectory)


def extract_x_percent_balanced(attack_df, normal_df, split):
    """
    Extracts a user-supplied percentage of the smallest of the attack or normal dataframes and creates a balanced
    training set by taking the same number of instances from the larger of the two, combining them. All dataframe
    entries not selected for the training set are added to a testing set
    :param attack_df: dataframe of attack data
    :param normal_df: dataframe of normal data
    :param split: percentage of data to use for training, as a decimal
    :return: train_df: dataframe of training set
    :return: test_df: dataframe of testing set
    """
    # Determine the sizes
    size_attack = len(attack_df)
    size_normal = len(normal_df)

    # Identify the smaller dataframe
    if size_attack < size_normal:
        smaller_df = attack_df
        larger_df = normal_df
        smaller_size = size_attack
    else:
        smaller_df = normal_df
        larger_df = attack_df
        smaller_size = size_normal

    # Calculate user supplied percentage of the smaller dataframe
    train_size = int(split * smaller_size)

    # Sample the training data
    train_smaller_df = smaller_df.sample(train_size)
    train_larger_df = larger_df.sample(train_size)

    # create the training set
    train_df = pd.concat([train_smaller_df, train_larger_df])

    # Get the remaining data for testing
    test_smaller_df = smaller_df.drop(train_smaller_df.index)
    test_larger_df = larger_df.drop(train_larger_df.index)

    # create the test set
    test_df = pd.concat([test_smaller_df, test_larger_df])

    return train_df, test_df


def train_evaluate_model(x_train_set, y_train_set, x_test_set, y_test_set, model_name):
    """
    Trains model and prints scores and confusion matrix. Saves png of confusion matrix
    :param x_train_set: training set with no class attribute
    :param y_train_set: class attributes for training
    :param x_test_set: test set with no class attribute
    :param y_test_set: set of the actual class values
    :param model_name: string name of the model being evaluated, for naming the png
    """
    # Train the model
    model.fit(x_train_set, y_train_set)

    # Evaluate the model
    y_pred = model.predict(x_test_set)

    print(" accuracy  = ", accuracy_score(y_test_set, y_pred), "\n",
          "precision = ", precision_score(y_test_set, y_pred), "\n",
          "recall    = ", recall_score(y_test_set, y_pred), "\n",
          "f1        = ", f1_score(y_test_set, y_pred), "\n",
          "confusion matrix: \n", confusion_matrix(y_test_set, y_pred))

    # save labeled confusion matrix as a png
    cm = confusion_matrix(y_test_set, y_pred, labels=model.classes_)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=model.classes_)
    disp.plot()
    plt.savefig('confusion_matrices/{}_confusion_matrix.png'.format(model_name))
    plt.close()


print("Enter the path to the directory containing normal pcap")
normal_directory = 'Data/normal'  # input()
normal_directory_obj = os.scandir(normal_directory)

print("Enter the path to the directory containing attack pcap")
attack_directory = input()  # 'attack_data'
attack_directory_obj = os.scandir(attack_directory)

print("Enter the path to the directory to output normal files into")
output_normal_directory = 'Results/normal/'  # input()

print("Enter the path to the directory to output attack files into")
output_attack_directory = 'Results/attack/'  # input()

os.system("mkdir -p {}".format(output_normal_directory))
os.system("mkdir -p {}".format(output_attack_directory))

print("What part of the pipeline would you like to run?\n1: flow generation\n2: data manipulation")
program_selection = input()

if program_selection == '1':

    print("Please enter the number associated with the desired flow generator:\n"
          "1: Zeek\n2: Argus\n3: Tranalyzer")
    flow_generator_selection = input()

    if flow_generator_selection == "1":
        # run zeek on pcap files
        call_zeek(normal_directory_obj, output_normal_directory)
        call_zeek(attack_directory_obj, output_attack_directory)

        os.system("~/zeekScripts/ZeekToCSV.sh {}".format(output_normal_directory))
        os.system("~/zeekScripts/ZeekToCSV.sh {}".format(output_attack_directory))

        print("Combining CSVs")
        os.system("cd {} && "
                  "rm *.log && "
                  "awk 'FNR==1 && NR!=1 {{next}} {{print}}' *.csv > combined.csv".format(output_normal_directory))
        print("Normal CSVs combined")
        os.system("cd {} && "
                  "rm *.log && "
                  "awk 'FNR==1 && NR!=1 {{next}} {{print}}' *.csv > combined.csv".format(output_attack_directory))
        print("Attack CSVs combined")
    elif flow_generator_selection == "2":
        # run argus on pcap files
        call_argus(normal_directory_obj, output_normal_directory)
        call_argus(attack_directory_obj, output_attack_directory)

        os.system("cd {} && "
                  "awk 'FNR==1 && NR!=1 {{next}} {{print}}' *.csv > combined.csv".format(output_normal_directory))

        os.system("cd {} && "
                  "awk 'FNR==1 && NR!=1 {{next}} {{print}}' *.csv > combined.csv".format(output_attack_directory))
    elif flow_generator_selection == "3":
        # run tranalyzer on pcap files
        call_tranalyzer(normal_directory_obj, output_normal_directory)
        call_tranalyzer(attack_directory_obj, output_attack_directory)

        os.chdir(output_normal_directory)
        # delete non flow files
        os.system("find . -type f ! -name '*flows.txt' -exec rm -f {} +")

        # run script to convert tab separated to comma separated
        os.system("cd ~ && ./tab_to_csv.sh {}".format(output_normal_directory))

        # combine all csv files together
        os.system("awk 'FNR==1 && NR!=1 {{next}} {{print}}' *flows.csv > combined.csv".format(output_normal_directory))

        # repeat above system calls for the attack directory
        os.chdir(os.path.expanduser('~') + "/{}".format(output_attack_directory))
        os.system("find . -type f ! -name '*flows.txt' -exec rm -f {} +")
        os.system("cd ~ && ./tab_to_csv.sh {}".format(output_attack_directory))
        os.system("awk 'FNR==1 && NR!=1 {{next}} {{print}}' *flows.csv > combined.csv")

elif program_selection == '2':

    # create two dataframes: one for normal and one for attack
    print("Creating Dataframes")

    # SHOULD UPDATE TO TAKE DTYPES FOR EACH FLOW ANALYZER
    normal_dataframe = pd.read_csv('{}/combined.csv'.format(output_normal_directory))
    print("Normal dataframe created")
    attack_dataframe = pd.read_csv('{}/combined.csv'.format(output_attack_directory))
    print("Attack dataframe created")

    # add corresponding attack label to the dataframes
    normal_dataframe['attack_label'] = 0
    attack_dataframe['attack_label'] = 1

    # get % for train/test split from user
    print("Enter percentage of data to use for training as a decimal. Ex: 70% = enter 0.7")
    split_value = 0.7  # float(input())

    if split_value > 1 or split_value < 0:
        print("Entry is not valid, please enter a value between 0 and 1")
        quit()

    # extract a given percentage of the smaller set
    train_dataframe, test_dataframe = extract_x_percent_balanced(attack_dataframe, normal_dataframe, split_value)

    # initialize preprocessor
    preprocessor = None

    # process data
    if train_dataframe.columns[0] == 'ts':  # zeek
        train_dataframe = train_dataframe.map(lambda x: np.nan if x == '-' else x)
        test_dataframe = test_dataframe.map(lambda x: np.nan if x == '-' else x)

        drop_features = ['ts', 'uid', 'proto', 'tunnel_parents', 'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p',
                         'conn_state', 'history', 'orig_ip_bytes', 'resp_ip_bytes', 'duration']

        train_dataframe.drop(columns=drop_features, inplace=True)
        test_dataframe.drop(columns=drop_features, inplace=True)

        categorical_features = ['service', 'local_orig', 'local_resp']

        numerical_features = ['orig_bytes', 'resp_bytes', 'missed_bytes',
                              'orig_pkts',  'resp_pkts']

        # Define the preprocessing for categorical features
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])

        # Define the preprocessing for numerical features
        numerical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='mean'))
        ])

        # Combine preprocessing steps
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, numerical_features),
                ('cat', categorical_transformer, categorical_features)
            ])

    elif train_dataframe.columns[0] == 'StartTime':  # argus

        drop_features = ['StartTime', 'Proto', 'SrcAddr', 'Sport', 'DstAddr', 'Dport']

        train_dataframe.drop(columns=drop_features, inplace=True)
        test_dataframe.drop(columns=drop_features, inplace=True)

        categorical_features = ['Flgs', 'Dir', 'State']
        numerical_features = ['TotPkts', 'TotBytes']

        # ensure TotPkts only contains numbers (can sometimes have other values due to column overhang on fixed width
        # columns generated by Argus)
        train_dataframe['TotPkts'] = (train_dataframe['TotPkts'].str.replace(r'[^0-9.]', '', regex=True)).astype(float)
        test_dataframe['TotPkts'] = (test_dataframe['TotPkts'].str.replace(r'[^0-9.]', '', regex=True)).astype(float)

        # Define the preprocessing for categorical features
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])

        # Define the preprocessing for numerical features
        numerical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='mean'))
        ])

        # Combine preprocessing steps
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, numerical_features),
                ('cat', categorical_transformer, categorical_features)
            ])

    elif train_dataframe.columns[0] == '%dir':  # tranalyzer

        categorical_features = ['%dir', 'flowStat', 'hdrDesc', 'ethType', 'tcpFStat', 'ipToS', 'ipFlags',
                                'ipOptCpCl_Num', 'tcpFlags', 'tcpAnomaly', 'tcpOptions', 'tcpStatesAFlags', 'icmpStat',
                                'icmpBFTypH_TypL_Code']

        numerical_features = ['duration', 'numHdrs', 'l4Proto', 'numPktsSnt', 'numPktsRcvd',
                              'numBytesSnt', 'numBytesRcvd', 'minPktSz', 'maxPktSz', 'avePktSize', 'stdPktSize',
                              'maxIAT', 'aveIAT', 'stdIAT', 'pktps', 'bytps', 'pktAsm', 'bytAsm', 'ipMaxdIPID',
                              'ipMinTTL', 'ipMaxTTL', 'ipTTLChg', 'ipOptCnt', 'tcpISeqN', 'tcpPSeqCnt',
                              'tcpSeqSntBytes', 'tcpSeqFaultCnt', 'tcpPAckCnt', 'tcpFlwLssAckRcvdBytes',
                              'tcpAckFaultCnt', 'tcpBFlgtMx', 'tcpInitWinSz', 'tcpAveWinSz', 'tcpMinWinSz',
                              'tcpMaxWinSz', 'tcpWinSzDwnCnt', 'tcpWinSzUpCnt', 'tcpWinSzChgDirCnt', 'tcpWinSzThRt',
                              'tcpOptPktCnt', 'tcpOptCnt', 'tcpMSS', 'tcpWS', 'tcpTmS', 'tcpTmER', 'tcpEcI', 'tcpUtm',
                              'tcpBtm', 'tcpSSASAATrip', 'tcpRTTAckTripMin', 'tcpRTTAckTripMax', 'tcpRTTAckTripAve',
                              'tcpRTTAckTripJitAve', 'icmpTCcnt', 'icmpEchoSuccRatio', 'icmpPFindex', 'connNumPCnt',
                              'connNumBCnt']

        drop_features = ['srcIP', 'srcPort', 'dstIP', 'dstPort', 'srcMac', 'dstMac', 'flowInd', 'vlanID',
                         'srcMacLbl_dstMacLbl', 'srcMac_dstMac_numP', 'connSipDprt', 'connDip', 'ipMindIPID',
                         'dstPortClassN', 'connF', 'connG', 'connSipDip', 'timeFirst', 'timeLast', 'srcIPCC',
                         'srcIPOrg', 'dstIPCC', 'dstIPOrg', 'numHdrDesc', 'macStat', 'macPairs', 'minIAT',
                         'ip6OptCntHH_D', 'ip6OptHH_D', 'tcpMPTBF', 'tcpMPF', 'tcpMPAID', 'tcpMPDSSF', 'icmpTmGtw',
                         'dstPortClass', 'connSip']

        train_dataframe.drop(columns=drop_features, inplace=True)
        test_dataframe.drop(columns=drop_features, inplace=True)

        # Define the preprocessing for categorical features
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])

        # Define the preprocessing for numerical features
        numerical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='mean'))
        ])

        # Combine preprocessing steps
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, numerical_features),
                ('cat', categorical_transformer, categorical_features)
            ])

    print("normal set size:", len(normal_dataframe))
    print("attack set size", len(attack_dataframe))
    print("training set size:", len(train_dataframe))
    print("test set size: ", len(test_dataframe))

    # prepare dataframes for input to a classifier
    X_train = train_dataframe.drop('attack_label', axis=1)
    y_train = train_dataframe['attack_label']
    X_test = test_dataframe.drop('attack_label', axis=1)
    y_test = test_dataframe['attack_label']

    print("Select a classifier by entering the corresponding number\n"
          "1: Naive Bayes\n2: K-Nearest Neighbours\n3: Random Forest\n4: Logistic Regression\n5: Decision Tree\n"
          "6: XGBoost\n7: Support Vector Machine\n8: Multi-Layer Perceptron")
    classifier_selection = input()

    if classifier_selection == '1':  # Naive Bayes
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', MultinomialNB())
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "naive_bayes")
    elif classifier_selection == '2':  # KNN
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', KNeighborsClassifier())
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "KNN")
    elif classifier_selection == '3':  # Random Forest
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', RandomForestClassifier(criterion='gini', verbose=10))
        ])
        
        train_evaluate_model(X_train, y_train, X_test, y_test, "random_forest")

        column_transformer = model.named_steps['preprocessor']
        feature_names = column_transformer.get_feature_names_out()

        # Get feature importance
        feature_importances = model.named_steps['classifier'].feature_importances_

        print("Number of features:", len(feature_names))
        print("Number of importances:", len(feature_importances))

        # Create a DataFrame for better visualization
        importance_df = pd.DataFrame({
            'Feature': feature_names,
            'Importance': feature_importances
        }).sort_values(by='Importance', ascending=False)

        print(importance_df.head(10))

    elif classifier_selection == '4':  # Logistic Regression
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', LogisticRegression(verbose=10))
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "logistic_regression")
    elif classifier_selection == '5':  # Decision Tree
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', DecisionTreeClassifier())
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "decision_tree")
    elif classifier_selection == '6':  # XGBoost
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', xgb.XGBClassifier())
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "xgboost")
    elif classifier_selection == '7':  # Support Vector Machine
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', SVC(verbose=10))
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "SVM")
    elif classifier_selection == '8':  # Multi-Layer Perceptron
        # Define the model
        model = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', MLPClassifier(verbose=10))
        ])

        train_evaluate_model(X_train, y_train, X_test, y_test, "perceptron")
