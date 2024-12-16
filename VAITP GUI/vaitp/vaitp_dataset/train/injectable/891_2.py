<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en"
      xmlns:tal="http://xml.zope.org/namespaces/tal"
      xmlns:metal="http://xml.zope.org/namespaces/metal"
      xmlns:i18n="http://xml.zope.org/namespaces/i18n"
      lang="en"
      i18n:domain="plone">

<head>

    <metal:block tal:define="dummy python:request.RESPONSE.setHeader('Content-Type', 'text/html;;charset=utf-8')" />

    <title tal:content="context/Title">
        Title
    </title>

    <style type="text/css" media="screen">
    body {
        background-color: white;
        color: black;
        font-family: "Lucida Grande", Verdana, Lucida, Helvetica, Arial, sans-serif;
        font-size: 69%;
    }

    a {
        display:block;
        margin: 0.5em;
        color: #436976;
        text-decoration: underline;
        line-height:1.5em;
    }

    img {
        border: 0px;
        padding: 5px;
    }

    #content-core {
        text-align: center;
    }

    </style>

</head>

<body>

<div id="content-core">
  <tal:block define="referer request/HTTP_REFERER;
                     url_tool nocall:context/portal_url;
                     referer python:referer if referer and url_tool.isURLInPortal(referer) else '';">
    <a href=""
       tal:attributes="href referer"
       tal:condition="referer"
       ><span i18n:translate="label_back_to_site">Back to site</span><br /><tal:block replace="structure context/tag" /></a>

    <a href=""
       tal:attributes="href python:url_tool()"
       tal:condition="not: referer"
       ><span i18n:translate="label_home">Home</span><br /><tal:block replace="structure context/tag" /></a>
      </tal:block>
</div>

</body>
</html>

