"""Koninklijke Philips N.V., 2019 - 2020. All rights reserved."""
from __future__ import print_function

import csv
import sys
import subprocess
import shutil
import os
import json
import xml.etree.ElementTree as ETree
import argparse

from guardrail_globals import GuardrailGlobals  # pylint: disable=E0401
import guardrails_log as cl  # pylint: disable=E0401

LOG = cl.get_logger()


def create_parser(args):
    """ Function which add the command line arguments required for
     the commandline input of guardrails"""
    # Create the parser
    func_parser = argparse.ArgumentParser(
        description='Guardrails for python programs')

    # Add the arguments
    func_parser.add_argument('--path',
                             metavar='--p',
                             type=str,
                             help='the Input file path for guardrail.ini')
    return func_parser.parse_args(args)


class Guardails(GuardrailGlobals):
    """
    This is a class for creating guardrails for python programs.

    Attributes:
       path_ini (string): The path to guardrail.ini file.
    """

    def __init__(self, path_ini):
        """
        The constructor for ComplexNumber class.

        Parameters:
          path_ini (string): The path to guardrail.ini file.

        """
        if sys.version_info >= (3, 5, 7):
            super(Guardails, self).__init__()  # python 2.7 does not support
        self.set_all(path_ini)

    def call_subprocess(self, cmd):  # pylint: disable=R0201
        """
        Function to call subprocess to issue system commands

        Parameters:
          cmd (string): command to be executed at system level.

        Returns:
        sub-process return value.
        """
        LOG.info("command for sub process:%s", str(cmd))  # pragma: no mutate
        retval = subprocess.call(cmd, shell=True)
        return retval

    def list_to_str_folders(self, folders=None):
        """
        Function to convert from list to string, all the folders for linting

        Parameters:
          folders (string): folders for the linting in .

        Returns:
        string which has folders.
        """
        if folders is None:
            folders = self.all_folders
        list_to_str = ''.join([str(elem) for elem in folders])
        LOG.info("list_to_str_folders function returned:%s",
                 str(list_to_str))  # pragma: no mutate
        return list_to_str

    @staticmethod
    def validate_return(val, message, guardrail):
        """
        Function to validate the returns from subprocess

        Parameters:
          val (int): return value from subprocess
          message (string): message to be printed.
          guardrail (bool): identifier whether a process or guardrail gate.

        Returns:
        sub-process return value.
        """
        process = "" if guardrail else "task"
        if val:
            msg = "Guardrail {}, failed {}.".format(process, message)
            LOG.info(msg)  # pragma: no mutate
            sys.exit(val)
        else:
            msg = "Guardrail {}, passed {}.".format(process, message)
            LOG.info(msg)  # pragma: no mutate
            return

    @staticmethod
    def file_exists(file_path):
        """
        Function to judge if a given file path is correct/Existing

        Parameters:
          file_path (string): path to the file

        Returns:
        None
        """
        if not os.path.exists(file_path):
            LOG.info("jscpd report not generated")  # pragma: no mutate
            print("\n\nGuardrail {}, failed {}.\n".
                  format("gating", "jscpd"))  # pragma: no mutate
            sys.exit(1)
        else:
            return

    def parse_jscpd_report_json(self, duplicate_limit, json_file):
        """
        Function to judge if JSCPD gating pass/fail

        Parameters:
          duplicate_limit (int): allowed duplicate limit for the jscpd/copy
           paste detection json_file (string): jscpd report file
           json_file: input data file

        Returns:
        return value. None
        """
        self.file_exists(json_file)
        try:
            with open(json_file, 'r') as data_file:
                data = json.load(data_file)
                per = float(data['statistics']['total']['percentage'])
                lines = int(data['statistics']['total']['lines'])
            if lines > 0:
                if per <= float(duplicate_limit):
                    LOG.info("Guardrail gating passed"
                             " jscpd")  # pragma: no mutate

                else:
                    LOG.info("Guardrail gating,"
                             " failed jscpd.")  # pragma: no mutate
                    sys.exit(1)
            else:
                LOG.info("jscpd report not correctly"
                         " generated")  # pragma: no mutate
                sys.exit(1)
        except KeyError:
            LOG.info("jscpd report not generated, key is not"
                     " found in json")  # pragma: no mutate
            sys.exit(1)

    @staticmethod
    def check_pass_fail(failure, total, allow_fail_per):
        """
        Function which check the failure percentile against total mutation runs
        Exits successfully if actual failure is equal or less than the
         specified allowed failure

        Parameters:
          failure (int): is the total of 'disabled + errors + failures'
          total (int): is the total number of test cases ran in mutmut
          allow_fail_per (int): allowed % of mutants to pass through

        Returns:
        None
        """
        per = int(total) * (allow_fail_per / 100)
        if total:
            if failure <= per:
                LOG.info("Guardrail gating,"
                         " passed mutation.")  # pragma: no mutate
            else:
                LOG.info("Guardrail gating,"
                         " failed mutation.")  # pragma: no mutate
                sys.exit(1)
        else:
            LOG.info("Guardrail gating, failed: mutation"
                     " test did not run.")  # pragma: no mutate
            sys.exit(1)

    @staticmethod
    def get_index_cnn(root):
        """
        Function to parse the xml file generated by lizard for cyclomatic
         complexity to identify the index of CNN

        Parameters:
          root (etree node): root node of the parsed xml

        Returns:
        (int) index of CNN in th xml
        """
        count = 0
        val = None
        try:
            labels = root.find('labels')
            for label in labels.iter('label'):
                if str(label.text).strip().upper() == str("CCN"):
                    val = count
                else:
                    count += 1
            return val
        except AttributeError:
            LOG.info("Guardrail unable to find the tag CCN"
                     " in the report ")  # pragma: no mutate
            sys.exit(1)

    def get_all_func_cnn(self, root):
        """
        Function which create a dictionary with all functions in the parsed
         files/source with their CNN

        Parameters:
          root (etree node): root node of the parsed xml

        Returns:
        (dictionary) with list of function names and its Cyclomatic complexity

        """
        temp_val = []
        cyclo_dict = dict()
        index = self.get_index_cnn(root)
        try:
            functions = root.findall('item')
            for item in functions:
                for cnn in item.iter('value'):
                    temp_val.append(cnn)
                cyclo_dict[str(item.attrib['name'])] = temp_val[index].text
                temp_val = []
            if not cyclo_dict:
                LOG.info("Guardrail unable to find the tags item/value/name"
                         " in the report file ")  # pragma: no mutate
                sys.exit(1)
            else:
                return cyclo_dict
        except KeyError:
            LOG.info("Guardrail unable to find the tags"
                     " item/value/name in the report ")  # pragma: no mutate
            sys.exit(1)

    def parse_cyclo_report_xml(self, xml_file):
        """ Function usd to fetch the necessary data from the xml
         output - lizard

        Parameters:
          xml_file (string): path to the xml file to be parsed

        Returns:
        (dictionary) with list of function names and its
         Cyclomatic complexity or None

        """
        try:
            root = ETree.parse(xml_file).getroot()
            for functions in root.iter('measure'):
                if functions.attrib['type'] == "Function":
                    LOG.info("successfully found functions"
                             " with CNN")  # pragma: no mutate
                    return self.get_all_func_cnn(functions)
            return None

        except IOError:
            LOG.info("cc.xml report file path")  # pragma: no mutate
            sys.exit(1)
        except KeyError:
            LOG.info("tags required are not found in cc.xml"
                     " report file path")  # pragma: no mutate
            sys.exit(1)

    def parse_mutmut_report_xml(self, allow_fail, xml_file):
        """ Function usd to fetch the necessary data from the
         xml output - mutmut

        Parameters:
          xml_file (string): path to the xml file to be parsed
          allow_fail(int) : allowd % of mutants to pass

        Returns:
        None

        """
        try:
            root = ETree.parse(xml_file).getroot()
            disabled = int(root.get('disabled'))
            errors = int(root.get('errors'))
            failures = int(root.get('failures'))
            tests = int(root.get('tests'))
            total_fail = disabled + errors + failures
            self.check_pass_fail(total_fail, tests, allow_fail)
        except IOError:
            LOG.info("mutmut.xml report file path cound"
                     " not be found")  # pragma: no mutate
            sys.exit(1)

    def guardrail_lint(self):
        """ Function which run the linting check
         (Static analysis for the files"""
        LOG.info("Started Linting gate")  # pragma: no mutate
        open(os.path.join(self.report_folder, "linting_Report.txt"), "w")
        cmd_list = self.generate_pylint_cmd()
        retval = (self.call_subprocess("%s >%s" %
                                       (cmd_list,
                                        os.path.join(
                                            self.report_folder,
                                            "linting_Report.txt"))))
        self.validate_return(retval, "Linting", True)
        print("Passed linting gate")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def guardrail_jscpd(self):
        """ Function which conduct copy past detection
         for the folders specified"""
        LOG.info("Started jscpd gate")  # pragma: no mutate
        retval = self.call_subprocess('jscpd --min-tokens %s  %s  --max-lines'
                                      ' 100000 --max-size 100mb --reporters '
                                      '"json,html" --mode "strict" %s -o %s %s'
                                      % (self.dup_token,
                                         self.jscpd_ignore_file(),
                                         self.jscpd_format(),
                                         self.report_folder,
                                         self.jscpd_root))
        self.validate_return(retval, "Copy Paste Detection report"
                                     " generation ", False)
        self.parse_jscpd_report_json(self.allow_dup, os.path.join(
            self.report_folder, "jscpd-report.json"))
        print("Passed JSCPD gating")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def guardrail_test(self):
        """ Function which conduct testing using pytest for the
         folders specified"""
        LOG.info("Started test gate")  # pragma: no mutate
        retval = self.call_subprocess('%s -m pytest %s %s --cov-report'
                                      ' "html" --cov=%s' %
                                      (self.python,
                                       self.pytest,
                                       self.cov_rc_file(),
                                       self.list_to_str_folders(
                                           self.src_folder)))
        self.validate_return(retval, "Test execution and coverage"
                                     " generation", False)
        print("Passed testing using pytest")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def guardrail_coverage(self):
        """
        Function which conduct coverage based on the test executed using
         pytest for the folders specified
        """
        LOG.info("Started coverage gate")  # pragma: no mutate
        retval = self.call_subprocess('%s -m coverage report'
                                      ' --fail-under=%s' % (self.python,
                                                            self.percent_cov))
        self.mov_cov_report()
        self.validate_return(retval, "Coverage threshold", True)
        print("Passed test coverage gating")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def mov_cov_report(self):
        """
        Function which is used to move the coverage report folder from where
         it generated to specified report folder
        """
        LOG.info("Started moving coverage file")  # pragma: no mutate
        dirpath = os.path.join(self.report_folder, "coverage_Report")
        if os.path.exists(dirpath) and os.path.isdir(dirpath):
            shutil.rmtree(dirpath)
        src = os.path.join(self.pytest, 'htmlcov')
        if os.path.exists(src) and os.path.isdir(src):
            shutil.move(src, dirpath)

    def guardrail_mutation(self):
        """ Function which is used to conduct the mutation testing and
         gate it with allowed mutants % """
        LOG.info("Started mutation gate")  # pragma: no mutate
        retval = self.call_subprocess('%s -m mutmut --paths-to-mutate %s'
                                      ' run || true' %
                                      (self.python,
                                       os.path.join(
                                           self.list_to_str_folders(
                                               self.src_folder))))
        self.validate_return(retval, "Mutation testing ", False)
        retval = self.call_subprocess(
            'python -m mutmut junitxml --suspicious-policy=ignore'
            ' --untested-policy=ignore > %s' % (
                os.path.join(self.report_folder, 'mutmut.xml')))
        self.validate_return(retval, "Mutation testing report"
                                     " generation", False)
        self.parse_mutmut_report_xml(self.allow_mutants, os.path.join(
            self.report_folder, 'mutmut.xml'))
        print("Passed mutation testing gate")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def guardrail_cyclomatic_complexity(self):
        """
        Function which is used to conduct the cyclomatic complexity
         and gate it with allowed cyclomatic complexity value
        """
        LOG.info("Started cyclomatic complexity gate")  # pragma: no mutate
        retval = self.call_subprocess('%s -m lizard %s %s -X > %s' %
                                      (self.python, os.path.join(
                                          self.list_to_str_folders(
                                              self.src_folder)),
                                       self.get_exclude_cc(),
                                       os.path.join(self.report_folder,
                                                    'CC.xml')))
        self.validate_return(retval, "Cyclomating complexity"
                                     " generation ", False)
        complexity = self.parse_cyclo_report_xml(os.path.join(
            self.report_folder, 'CC.xml'))
        cyclo_complex = [cyclo_complex + "," + str(int(
            complexity.get(cyclo_complex))) for
                         cyclo_complex in complexity if int(
                             complexity.get(cyclo_complex)) > self.cc_limit]
        cyclo_repport = open(os.path.join(self.report_folder,
                                          "cyclo_failure.csv"), "w")
        csv.writer(cyclo_repport, delimiter=',').writerows(
            [x.split(',') for x in cyclo_complex])
        cyclo_repport.close()
        self.validate_return(len(cyclo_complex), "Cyclomatic complexity", True)
        print("Passed Cyclomatic complexity gating")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def guardrail_deadcode(self):
        """ Function which is used to conduct the dead code analysis and
         gate it """
        LOG.info("Started deadcode gate")  # pragma: no mutate
        retval = self.call_subprocess('%s -m vulture %s  %s %s'
                                      ' --min-confidence %s >%s' %
                                      (self.python, self.list_to_str_folders(),
                                       self.dead_code_exclude(),
                                       self.dead_code_whitelist,
                                       self.min_deadcode_confidence,
                                       os.path.join(self.report_folder,
                                                    'deadcode.txt')))
        self.validate_return(retval, "Dead code detection ", True)
        print("Passed Dead code gating")  # pragma: no mutate
        print('====================================')  # pragma: no mutate

    def check_report_dir(self):
        """ Function which is used to check if report path is available """
        if not os.path.exists(self.report_folder):
            os.makedirs(self.report_folder)

    @staticmethod
    def clean_log():
        """ Function to clean the log file"""
        ini_path = os.path.abspath(os.path.join
                                   (os.path.dirname(__file__), os.pardir))
        file_name = os.path.join(ini_path, "guardrails", "guardrails.log")
        if os.path.exists(file_name):
            open(file_name, 'w').close()

    def orchestrate_guardrails(self):
        """ Function which is used to orchestrate all the activities
         of guardrails """
        self.clean_log()
        cstr = "Guardrails for python programs"
        LOG.info(cstr.center(40, '#'))  # pragma: no mutate
        print("\n\n" + cstr.center(40, '#'))  # pragma: no mutate
        self.check_report_dir()
        if self.linting: self.guardrail_lint()
        if self.cpd: self.guardrail_jscpd()
        if self.deadcode: self.guardrail_deadcode()
        if self.cycloc: self.guardrail_cyclomatic_complexity()
        if self.cov:
            self.guardrail_test()
            self.guardrail_coverage()
        if self.mutation: self.guardrail_mutation()
