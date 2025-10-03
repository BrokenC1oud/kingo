import base64
import logging
import re
from datetime import datetime
from functools import cached_property
from pprint import pprint
from typing import Optional

import STPyV8
import requests
from bs4 import BeautifulSoup
from pydantic import Field, BaseModel, AliasChoices

from secret import *

requests.packages.urllib3.util.connection.HAS_IPV6 = False

HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Linux"',
}

JS_PATTERN = r"var\s+(\w+)\s*=\s*['\"]([^'\"]*)['\"]"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

class KingoEncypt(BaseModel):
    decrypt_key: str = Field(validation_alias=AliasChoices("_tdeskey"))
    session_id: str = Field(validation_alias=AliasChoices("_tsessionid"))

class MainInfo(BaseModel):
    username: int = Field(validation_alias=AliasChoices("_loginid"))
    name: str = Field(validation_alias=AliasChoices("_userName"))
    school_year: int = Field(validation_alias=AliasChoices("_currentXn"))
    semester: int = Field(validation_alias=AliasChoices("_currentXq"))
    term_desc: str = Field(validation_alias=AliasChoices("_xnxqDesc"))
    school_code: int = Field(validation_alias=AliasChoices("G_SCHOOL_CODE"))
    school_name: str = Field(validation_alias=AliasChoices("G_SCHOOL_NAME"))

    user_code: int = Field(validation_alias=AliasChoices("G_USER_CODE"))

class KingoSignResult(BaseModel):
    message: str
    result: str
    status: int

class Announcement(BaseModel):
    title: str
    notice_id: int
    pinned: bool
    date: datetime

class ClassSchedule(BaseModel):
    day_of_week: int
    period: int
    name: str
    teacher: str
    weeks: str
    location: str

class Kingo:
    def __init__(self, username: str = USERNAME, password: str = PASSWORD, domain: str = DOMAIN):
        self.username = username
        self.password = password
        self.domain = domain

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

        self.login_action = self.session.get(f'https://{self.domain}/', allow_redirects=True)
        self.login_action.raise_for_status()
        logging.info(f"JSESSIONID: {self.session.cookies['JSESSIONID']}")

        # Set Encypt
        self.set_kingo_encypt = self.session.get(f"https://{self.domain}/custom/js/SetKingoEncypt.jsp",
                                       params={"t": self.get_t(self.login_action.text, "/custom/js/SetKingoEncypt.jsp")})
        # Get Encypt
        get_kingo_encypt = self.session.get(f"https://{self.domain}/custom/js/GetKingoEncypt.jsp",
                                       params={"t": self.get_t(self.login_action.text, "/custom/js/GetKingoEncypt.jsp")})
        self.kingo_encypt = KingoEncypt.model_validate({k: v for k, v in re.findall(JS_PATTERN, get_kingo_encypt.text)})
        logging.info(f"kingo_encypt: {self.kingo_encypt}")


    @cached_property
    def signed(self) -> bool:
        md5_js = self.session.get(f"https://{self.domain}/custom/js/md5.js",
                                  params={"t": self.get_t(self.login_action.text, "/custom/js/md5.js")})
        base64_js = self.session.get(f"https://{self.domain}/custom/js/base64.js",
                                     params={"t": self.get_t(self.login_action.text, "/custom/js/base64.js")})
        jkingo_des_js = self.session.get(f"https://{self.domain}/custom/js/jkingo.des.js",
                                         params={"t": self.get_t(self.login_action.text, "/custom/js/jkingo.des.js")})

        with STPyV8.JSContext() as ctx:
            ctx.eval(md5_js.text)
            ctx.eval(base64_js.text)
            ctx.eval(jkingo_des_js.text)
            ctx.eval("\n".join([_ for _ in self.set_kingo_encypt.text.split("\n") if not _.startswith("document")]))

            username = ctx.eval(f"""base64encode("{self.username}" + ";;" + "{self.session.cookies['JSESSIONID']}")""")
            password = ctx.eval(f"""hex_md5(hex_md5("{self.password}") + hex_md5(""))""")
            params = ctx.eval(
                f"""getEncParams("_u={username}&_p={password}&randnumber=&isPasswordPolicy=false&txt_mm_expression=&txt_mm_length=&txt_mm_userzh=&hid_flag=1&hidlag=1&hid_dxyzm=")+"&deskey="+"{self.kingo_encypt.decrypt_key}"+"&_ssessionid="+"{self.kingo_encypt.session_id}" """)
            logging.debug(params)

        cas_logon_action = self.session.post(f"https://{self.domain}/cas/logon.action", data=dict(pair.split("=") for pair in params.split("&")))
        logging.debug(cas_logon_action.status_code)
        logging.debug(cas_logon_action.json())
        logging.info(f"New JSESSIONID: {self.session.cookies['JSESSIONID']}")

        res = KingoSignResult.model_validate(cas_logon_action.json())
        if res.status != 200:
            logging.error(res.message)
            return False
        else:
            return True


    @cached_property
    def main_info(self) -> MainInfo:
        main_info = self.session.get(f"https://{self.domain}/frame/home/js/SetMainInfo.jsp", params={"v": 250701})
        main_info = re.findall(JS_PATTERN, "\n".join([_ for _ in main_info.text.split("\n") if not _.startswith("document")]))
        main_info = {k: v for k, v in main_info}
        main_info = MainInfo.model_validate(main_info)
        return main_info


    @cached_property
    def announcements(self) -> list[Announcement]:
        bbs_school_notice = self.session.post(f"https://{self.domain}/cms/bbsSchoolNotice.action", params={"recordsPerPage": 8})

        soup = BeautifulSoup(bbs_school_notice.text, "lxml")
        announcements = []
        rows = soup.select("#schoolnotice_div tbody tr")

        for row in rows:
            link = row.find('a')
            if link:
                title = link.get_text(strip=True)

                onclick = link.get("href", "")
                notice_id_match = re.search(r"toschoolnotice\('([^']+)'\)", onclick)
                notice_id = notice_id_match.group(1) if notice_id_match else None

                is_pinned = row.find('span', style=lambda x: x and 'color: red' in x) is not None

                date_td = row.find_all('td')[1]
                date = date_td.get_text(strip=True)

                announcements.append(
                    Announcement(
                        title=title,
                        notice_id=notice_id,
                        pinned=is_pinned,
                        date=date,
                    )
                )

        return announcements


    def schedule(self, school_year: int, semester: int) -> list[ClassSchedule]:
        time_periods = {
            '一': 1,
            '二': 2,
            '三': 3,
            '四': 4,
            '五': 5,
        }
        days = ['星期一', '星期二', '星期三', '星期四', '星期五', '星期六', '星期日']

        result: list[ClassSchedule] = []

        schedule = self.session.get(f"https://{self.domain}/student/wsxk.xskcb10319.jsp",
                                    params={"params": base64.b64encode(f"xn={school_year}&xq={semester}&xh={self.main_info.user_code}".encode("utf-8"))},
                                    headers={"Referer": f"https://{self.domain}/student/xkjg.wdkb.jsp"})

        soup = BeautifulSoup(schedule.text, "lxml")
        main_table = soup.find("table", id="mytable")
        if main_table:
            rows = main_table.find("tbody").find_all("tr")
            for row in rows[1:]:
                cells = row.find_all("td", class_="td")

                period_cell = row.find("td", class_="td1", rowspan=None)
                if period_cell and period_cell.get_text(strip=True) in time_periods:
                    period = time_periods[period_cell.get_text(strip=True)]
                else:
                    continue

                for day_idx, cell in enumerate(cells):
                    if day_idx >= len(days):
                        break
                    course_divs = cell.find_all("div", style=re.compile('padding-bottom'))

                    for course_div in course_divs:
                        course_text = course_div.get_text(strip=True)

                        if course_text:
                            lines = [line.strip() for line in course_div.stripped_strings]

                            if len(lines) >= 3:
                                result.append(ClassSchedule(
                                    day_of_week=day_idx + 1,
                                    period=period,
                                    name=lines[0],
                                    teacher=lines[1],
                                    weeks=lines[2],
                                    location=lines[3] if len(lines) > 3 else '',
                                ))

        return result


    @staticmethod
    def get_t(source: str, url: str) -> Optional[str]:
        soup = BeautifulSoup(source, "lxml")

        script_tags = soup.find_all("script", src=True)
        for script in script_tags:
            src = script.get("src")
            if '?' in src:
                path, params = src.split('?')
                if path == url:
                    return params.split('=')[1]
        return None


if __name__ == "__main__":
    kingo = Kingo()
    if kingo.signed:
        print("Login Successful")
    else:
        print("Login Failed")
    schedule = kingo.schedule(school_year=2025, semester=0)
    pprint(schedule)
