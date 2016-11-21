import re
import codecs

def valid_month(month):
    months = ['January',
              'February',
              'March',
              'April',
              'May',
              'June',
              'July',
              'August',
              'September',
              'October',
              'November',
              'December']

    month_abbvs = dict((m[:3].lower(),m) for m in months)
    if month:
      new_month = month[:3].lower()
      return month_abbvs.get(new_month)

def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if day > 0 and day <= 31:
            return day

def valid_year(year):
    if year and year.isdigit():
        year = int(year)
        if year >= 1900 and year <= 2020:
            return year

def rot13(user_input):
    if user_input:
      return codecs.encode(user_input, 'rot_13')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or PASS_RE.match(email)

def escape_html(s):
    if s == '>':
      return '&gt;'
    elif s == '<':
      return '&lt;'
    elif s == '"':
      return '&quot;'
    elif s == '&':
      return '&amp;'
    else:
      return s