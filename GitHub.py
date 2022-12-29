import json
import os
import sys
import time
from typing import List
from datetime import datetime
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, Identity, Vulnerability, Report
import subprocess
from pathlib import Path

import csv
import logging
# 华为软件列表的集合，只能由 get_huawei_software_set 函数调用
_software_set = set()


def get_huawei_software_set():
    """
    获取华为软件列表，并将结果保存在全局变量 software_set 中
    :return:
    """
    global _software_set
    if len(_software_set) != 0:
        return _software_set
    p = Path(__file__).parent 
    with open(p / "huawei-open-source-software.csv", "r",encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            _software_set.add(row[0])
    return _software_set

class Github:
    def __init__(
            self,
            GHSA_ID,
            advisory_database_url,
            modified,
            published,
            CVE,
            CVSS_severity,
            cwe_ids,
            CVSS_base_metrics,
            summary,#标题
            references,
            affected,
            details,
            description_md
    ):
        self.GHSA_ID = GHSA_ID
        self.name = f"GITHUB:{GHSA_ID}"
        self.advisory_database_url= advisory_database_url
        self.modified = modified
        self.published = published
        self.CVE= CVE
        self.CVSS_severity = CVSS_severity
        self.cwe_ids = cwe_ids
        if CVSS_base_metrics == "":
            self.CVSS_base_metrics = None
        else:
            self.CVSS_base_metrics = CVSS_base_metrics
        if summary == "":
            self.summary = None
        else:
            self.summary = summary
        self.references = references
        if details == "":
            self.details = None
        else:
            self.details= details
        self.affected = affected
        self.description_md: str = description_md


        # 按照华为软件列表打标签
        self.labels = []
        self.software = None
        software_set = get_huawei_software_set()
        words = self.details.split()
        for word in words:
            if word in software_set:
                self.labels = ["HUAWEI"]
                self.software = word
                break


class GitHubConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.cve_map = {}
        self.githubs: List[Github] = []


    def update_data(self):
        #github
        # subprocess.run(["git", "pull"], cwd=None, check=True)

        p = Path(__file__).parent

        with open(p / "GitHub.csv", "r", encoding='utf-8') as f:
            reader = csv.reader(f)
            # read header
            next(reader)
            for row in reader:
                (
                    GHSA_ID,
                    advisory_database_url,
                    modified,
                    published,
                    CVE,
                    CVSS_severity,
                    cwe_ids,
                    CVSS_base_metrics,
                    summary,
                    references,
                    details,
                    affected,
                    description_md
                ) = row
                # TODO: description 未定义，可以把 details 之类的作为 description，references opencti 有专门的方式表示，可以不放在 description 里
                #根据学长您的建议，我把这些属性放入description_md这里
                description_md = (
                    f"summary : {summary } \n\n "
                    f"details: {details} \n\n"
                    f"advisory_database_url: {advisory_database_url} \n\n "
                    f"CVSS_severity: {CVSS_severity} \n\n "
                    f"cwe_ids: {cwe_ids} \n\n "
                    f"CVSS_base_metrics: {CVSS_base_metrics} \n\n "
                    f"affected: {affected} \n\n "

                )
                json_file = p / "github-data" / f"{GHSA_ID}.json"#json文件，压缩包里面有每条数据的json文件
                if json_file.exists():
                    with open(json_file, "r") as f2:
                        data = json.load(f2)
                        description_md += f'\n\n ```\n{data["code"]}\n```'
                # TODO: GitHub 类实例化参数要对应
                #已经对应，学长可以看一下
                github = Github(
                    GHSA_ID,
                    advisory_database_url,
                    modified,
                    published,
                    CVE,
                    CVSS_severity,
                    cwe_ids,
                    CVSS_base_metrics,
                    summary,
                    references,
                    details,
                    affected,
                    description_md,
                )
                self.githubs.append(github)
                CVE: str
                if CVE != "":
                    self.cve_map[f"{GHSA_ID}"] = CVE.split(" ")

    def send_data(self):
        self.update_data()

        bundle = []

        # stix 以 name 字符串和类型唯一标识一个对象
        author = stix2.Identity(
            id=Identity.generate_id("Github", "organization"),
            name="Github",
            identity_class="organization",
        )
        bundle.append(author)

        for github in self.githubs:
            external_reference = stix2.ExternalReference(
                source_name="Github", url=github.references    #references放入这里
            )

            report_refs = [author]

            #TODO: 要链接到 cve_id，可以参考 0day 的写法
            #根据CVE链接到cve_id
            # add github relation
            if github.GHSA_ID in self.cve_map:
                for cve_id in self.cve_map[github.GHSA_ID]:
                    report_refs.append(Vulnerability.generate_id(cve_id))

            if github.software is not None:
                logging.info(f"software: {github.software}")
                software = stix2.Software(name=github.software)
                report_refs.append(software)
                bundle.append(software)
            else:
                logging.info(f"software: None")

            report = stix2.Report(
                id=Report.generate_id(github.name, datetime(1970, 1, 1)),
                name=github.name,
                description=github.description_md,
                created_by_ref=author,
                external_references=[external_reference],
                object_refs=report_refs,
                published=github.published,#两个时间，我根据opencti里面，应该是放到这
                modified=github.modified,
                # published_opencti=datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z"),#传进opencti的时间
                labels=github.labels,
            )

            bundle.append(report)

        bundle = stix2.Bundle(bundle, allow_custom=True)

        # 在发送数据前前记录时间，创建 work
        timestamp = int(time.time())
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = "github run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        # 发送数据到 OpenCTI
        self.helper.send_stix2_bundle(
            bundle.serialize(),
            entities_types=self.helper.connect_scope,
            work_id=work_id,
            update=True,
        )

        # 运行结束后，记录日志
        self.helper.log_info(
            "Connector successfully run, storing last_run as " + str(timestamp)
        )
        self.helper.set_state({"last_run": timestamp})
        message = "Last_run stored, next run in: 1 days"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)

    ####
    # For details: see
    # https://luatix.notion.site/luatix/Connector-Development-06b2690697404b5ebc6e3556a1385940
    ##
    def run(self):
        # todo loop
        while True:
            self.send_data()
            print("done")
            time.sleep(3600 * 24)


if __name__ == "__main__":
    try:
        connector = GitHubConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

