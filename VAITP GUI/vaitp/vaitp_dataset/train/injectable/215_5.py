```python
import os
import sys
import tempfile

import pytest
import setpath  # noqa:F401, must come before 'import mechanicalsoup'
from bs4 import BeautifulSoup
from requests.cookies import RequestsCookieJar
from utils import mock_get, prepare_mock_browser

import mechanicalsoup


def test_submit_online(httpbin):
    """Complete and submit the pizza form at http://httpbin.org/forms/post """
    browser = mechanicalsoup.Browser()
    page = browser.get(httpbin + "/forms/post")
    form = page.soup.form

    form.find("input", {"name": "custname"})["value"] = "Philip J. Fry"
    # leave custtel blank without value
    assert "value" not in form.find("input", {"name": "custtel"}).attrs
    form.find("input", {"name": "size", "value": "medium"})["checked"] = ""
    form.find("input", {"name": "topping", "value": "cheese"})["checked"] = ""
    form.find("input", {"name": "topping", "value": "onion"})["checked"] = ""
    form.find("textarea", {"name": "comments"}).insert(0, "freezer")

    response = browser.submit(form, page.url)

    # helpfully the form submits to http://httpbin.org/post which simply
    # returns the request headers in json format
    json = response.json()
    data = json["form"]
    assert data["custname"] == "Philip J. Fry"
    assert data["custtel"] == ""  # web browser submits "" for input left blank
    assert data["size"] == "medium"
    assert data["topping"] == ["cheese", "onion"]
    assert data["comments"] == "freezer"

    assert json["headers"]["User-Agent"].startswith('python-requests/')
    assert 'MechanicalSoup' in json["headers"]["User-Agent"]


def test_get_request_kwargs(httpbin):
    """Return kwargs without a submit"""
    browser = mechanicalsoup.Browser()
    page = browser.get(httpbin + "/forms/post")
    form = page.soup.form
    form.find("input", {"name": "custname"})["value"] = "Philip J. Fry"
    request_kwargs = browser.get_request_kwargs(form, page.url)
    assert "method" in request_kwargs
    assert "url" in request_kwargs
    assert "data" in request_kwargs
    assert ("custname", "Philip J. Fry") in request_kwargs["data"]


def test_get_request_kwargs_when_method_is_in_kwargs(httpbin):
    """Raise TypeError exception"""
    browser = mechanicalsoup.Browser()
    page = browser.get(httpbin + "/forms/post")
    form = page.soup.form
    kwargs = {"method": "post"}
    with pytest.raises(TypeError):
        browser.get_request_kwargs(form, page.url, **kwargs)


def test_get_request_kwargs_when_url_is_in_kwargs(httpbin):
    """Raise TypeError exception"""
    browser = mechanicalsoup.Browser()
    page = browser.get(httpbin + "/forms/post")
    form = page.soup.form
    kwargs = {"url": httpbin + "/forms/post"}
    with pytest.raises(TypeError):
        browser.get_request_kwargs(form, page.url, **kwargs)


def test__request(httpbin):
    form_html = f"""
    <form method="post" action="{httpbin.url}/post">
      <input name="customer" value="Philip J. Fry"/>
      <input name="telephone" value="555"/>
      <textarea name="comments">freezer</textarea>
      <fieldset>
        <legend> Pizza Size </legend>
        <p><input type=RADIO name=size value="small">Small</p>
        <p><input type=radiO name=size value="medium" checked>Medium</p>
        <p><input type=radio name=size value="large">Large</p>
      </fieldset>
      <fieldset>
        <legend> Pizza Toppings </legend>
        <p><input type=CHECKBOX name="topping" value="bacon" checked>Bacon</p>
        <p><input type=checkBox name="topping" value="cheese">Extra Cheese</p>
        <p><input type=checkbox name="topping" value="onion" checked>Onion</p>
        <p><input type=checkbox name="topping" value="mushroom">Mushroom</p>
      </fieldset>
      <select name="shape">
        <option value="round">Round</option>
        <option value="square" selected>Square</option>
      </select>
    </form>
    """

    form = BeautifulSoup(form_html, "lxml").form

    browser = mechanicalsoup.Browser()
    response = browser._request(form)

    data = response.json()['form']
    assert data["customer"] == "Philip J. Fry"
    assert data["telephone"] == "555"
    assert data["comments"] == "freezer"
    assert data["size"] == "medium"
    assert data["topping"] == ["bacon", "onion"]
    assert data["shape"] == "square"

    assert "application/x-www-form-urlencoded" in response.request.headers[
        "Content-Type"]


valid_enctypes_file_submit = {"multipart/form-data": True,
                              "application/x-www-form-urlencoded": False
                              }

default_enctype = "application/x-www-form-urlencoded"


@pytest.mark.parametrize("file_field", [
  """<input name="pic" type="file" />""",
  ""])
@pytest.mark.parametrize("submit_file", [
    True,
    False
])
@pytest.mark.parametrize("enctype", [
  pytest.param("multipart/form-data"),
  pytest.param("application/x-www-form-urlencoded"),
  pytest.param("Invalid enctype")
])
def test_enctype_and_file_submit(httpbin, enctype, submit_file, file_field):
    # test if enctype is respected when specified
    # and if files are processed correctly
    form_html = f"""
    <form method="post" action="{httpbin.url}/post" enctype="{enctype}">
      <input name="in" value="test" />
      {file_field}
    </form>
    """
    form = BeautifulSoup(form_html, "lxml").form

    valid_enctype = (enctype in valid_enctypes_file_submit and
                     valid_enctypes_file_submit[enctype])
    expected_content = b""  # default
    if submit_file and file_field:
        # create a temporary file for testing file upload
        file_content = b":-)"
        pic_filedescriptor, pic_path = tempfile.mkstemp()
        pic_filename = os.path.basename(pic_path)
        os.write(pic_filedescriptor, file_content)
        os.close(pic_filedescriptor)
        if valid_enctype:
            # Correct encoding => send the content
            expected_content = file_content
        else:
            # Encoding doesn't allow sending the content, we expect
            # the filename as a normal text field.
            expected_content = os.path.basename(pic_path.encode())
        tag = form.find("input", {"name": "pic"})
        tag["value"] = open(pic_path, "rb")

    browser = mechanicalsoup.Browser()
    response = browser._request(form)

    if enctype not in valid_enctypes_file_submit:
        expected_enctype = default_enctype
    else:
        expected_enctype = enctype
    assert expected_enctype in response.request.headers["Content-Type"]

    resp = response.json()
    assert resp["form"]["in"] == "test"

    found = False
    found_in = None

    for key, value in resp.items():
        if value:
            if "pic" in value:
                content = value["pic"].encode()
                assert not found
                assert key in ("files", "form")
                found = True
                found_in = key
            if key == "files" and not valid_enctype:
                assert not value

    assert found == bool(file_field)
    if file_field:
        assert content == expected_content

        if valid_enctype:
            assert found_in == "files"
            if submit_file:
                assert ("filename=\"" + pic_filename + "\""
                        ).