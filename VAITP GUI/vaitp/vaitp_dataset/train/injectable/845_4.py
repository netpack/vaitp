<?xml version="1.1" encoding="UTF-8"?>

<!--
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
-->

<xwikidoc version="1.5" reference="XWiki.ClassSheet" locale="">
  <web>XWiki</web>
  <name>ClassSheet</name>
  <language/>
  <defaultLanguage/>
  <translation>0</translation>
  <creator>xwiki:XWiki.Admin</creator>
  <parent>XWiki.XWikiClasses</parent>
  <author>xwiki:XWiki.Admin</author>
  <contentAuthor>xwiki:XWiki.Admin</contentAuthor>
  <version>1.1</version>
  <title>#sheetTitle('platform.xclass.defaultClassSheet.title')</title>
  <comment/>
  <minorEdit>false</minorEdit>
  <syntaxId>xwiki/2.0</syntaxId>
  <hidden>true</hidden>
  <content>{{template name="locationPicker_macros.vm" /}}

{{velocity}}
## This document can be copied in order to be customized so we cannot rely on its name to determine if the currently
## displayed document is a class or the class sheet itself. We look for the sheet descriptor instead.
#set ($isSheet = $doc.getObject('XWiki.SheetDescriptorClass'))
#if ($isSheet)
  ## Viewing the sheet document itself.
  {{translation key="platform.xclass.defaultClassSheet.description"/}}
#elseif ("$!request.bindSheet" != '' &amp;&amp; $hasEdit)
  #if ($services.csrf.isTokenValid($request.getParameter('form_token')))
    ## Bind the sheet to the class.
    #set ($classSheetReference = $services.model.resolveDocument($request.bindSheet))
    #if ($services.sheet.bindClassSheet($doc, $classSheetReference))
      $doc.save($services.localization.render('platform.xclass.defaultClassSheet.sheets.bind'))
    #end
    $response.sendRedirect($request.xredirect)
  #else
    $response.sendRedirect($services.csrf.getResubmissionURL())
  #end
  ## Stop processing, since we already sent a redirect.
  #stop
#elseif("$!request.docName" != '')
  ## Request for creating a new instance.
  ## We don't actually create a new instance here, we just redirect to the edit mode.
  #set ($targetSpaceRef = $services.model.resolveSpace($request.spaceName))
  #set ($targetDocRef = $services.model.createDocumentReference($request.docName, $targetSpaceRef))
  #if (!$xwiki.exists($targetDocRef) &amp;&amp; $services.security.authorization.hasAccess('edit', $targetDocRef))
    ## Compute the default edit mode to ensure backward compatibility with documents that are still using the deprecated
    ## inline action.
    #set ($editAction = $xwiki.getDocument($request.template).getDefaultEditMode())
    $response.sendRedirect($xwiki.getURL($targetDocRef, $editAction, $escapetool.url({
      'template': $request.template,
      'parent': $request.parent,
      'title': $request.docName
    })))
    ## Stop processing, since we already sent a redirect.
    #stop
  #end
#end
{{/velocity}}

{{velocity}}
## If this sheet is explicitly bound to the displayed class then print the class document content before the
## sheet output. Class authors can put the description of the class in the class document content.
#set($classSheetReference = $services.model.createDocumentReference($doc.wiki, 'XWiki', 'ClassSheet'))
#if($services.sheet.getDocumentSheets($doc).contains($classSheetReference))
  {{include reference="" /}}
#end
{{/velocity}}

{{velocity}}
#if (!$isSheet)
  #set ($className = $doc.pageReference.name)
  #set ($className = $stringtool.removeEnd($className, 'Class'))
  ## Determine the class sheets.
  #set ($classSheetReferences = $services.sheet.getClassSheets($doc))
  #if ($classSheetReferences.isEmpty())
    ## There is no class sheet explicitly bound to this class. Fall-back on naming convention.
    ## Before XWiki 2.0, the default class sheet was suffixed with "ClassSheet". Since 2.0, the suffix is just "Sheet".
    #set ($defaultClassSheetReference = $services.model.createDocumentReference("${className}ClassSheet",
      $doc.documentReference.parent))
    #if (!$xwiki.exists($defaultClassSheetReference))
      #set ($defaultClassSheetReference = $services.model.createDocumentReference("${className}Sheet",
        $doc.documentReference.parent))
    #end
  #end
  ## Determine the template using naming convention.
  ## Before XWiki 2.0, the default class template was suffixed with "ClassTemplate".
  ## Since 2.0, the suffix is just "Template".
  #set ($classTemplateReference = $services.model.createDocumentReference("${className}ClassTemplate",
    $doc.documentReference.parent))
  #if (!$xwiki.exists($classTemplateReference))
    #set ($classTemplateReference = $services.model.createDocumentReference("${className}Template",
      $doc.documentReference.parent))
  #end
  ## Determine the template provider using naming convention.
  #set ($classTemplateProviderReference = $services.model.createDocumentReference("${className}TemplateProvider",
    $doc.documentReference.parent))
  #set ($classTemplateProviderDoc = $xwiki.getDocument($classTemplateProviderReference))
  #set ($hasClassTemplateProvider = !$classTemplateProviderDoc.isNew())
  #set($classTemplateDoc = $xwiki.getDocument($classTemplateReference))
  #set($hasClassSheets = !$classSheetReferences.isEmpty() || $xwiki.exists($defaultClassSheetReference))
  #set($hasClassTemplate = !$classTemplateDoc.isNew())
  #if(!$defaultSpace)
    #set($defaultSpace = $doc.space)
  #end
  #if(!$defaultParent)
    #set($defaultParent = ${doc.fullName})
  #end

  #set ($classEditorURL = $doc.getURL('edit', 'editor=class'))
  #if($doc.getxWikiClass().properties.size() == 0)
    #set ($openLink = "&lt;a href='$escapetool.xml($classEditorURL)'&gt;")
    #set ($closeLink = '&lt;/a&gt;')
    {{warning}}
      {{html}}
      ## First escape the content of the translation, then replace the placeholders with content that would otherwise be
      ## escaped during the first escaping.
      #set ($warningMessage = $services.localization.render('platform.xclass.defaultClassSheet.properties.empty', 
        ['__OPEN_LINK__', '__CLOSE_LINK__']))
      $escapetool.xml($warningMessage).replace('__OPEN_LINK__', $openLink).replace('__CLOSE_LINK__', $closeLink)
      {{/html}}
    {{/warning}}
  #else
    (% id="HClassProperties" %)
    = {{translation key="platform.xclass.defaultClassSheet.properties.heading"/}} =
    #foreach($property in $doc.getxWikiClass().properties)
      * $services.rendering.escape("$property.prettyName ($property.name: $xwiki.metaclass.get($property.classType).prettyName)", $xwiki.currentContentSyntaxId)
    #end
    #set ($openLink = "&lt;a href='$escapetool.xml($classEditorURL)'&gt;")
    #set ($closeLink = '&lt;/a&gt;')
    #set ($warningMessage = $escapetool.xml($services.localization.render('platform.xclass.defaultClassSheet.properties.edit', ['__OPEN_LINK__', '__CLOSE_LINK__'])))
    ## First escape the content of the translation, then replace the placeholders with content that would otherwise be
    ## escaped during the first escaping.
    * //{{html}}$warningMessage.replace('__OPEN_LINK__', $openLink).replace('__CLOSE_LINK__', $closeLink){{/html}}//

  #end
  #if ($hasClassSheets &amp;&amp; $hasClassTemplate)
    (% id="HCreatePage" %)
    = {{translation key="platform.xclass.defaultClassSheet.createPage.heading"/}} =
    #if("$!targetDocRef" != '' &amp;&amp; $xwiki.exists($targetDocRef))
      {{warning}}
        {{html}}
          #set ($targetDocLink = $xwiki.getURL($targetDocRef))
          #set ($openLink = "&lt;a href='$escapetool.xml($targetDocLink)'&gt;")
          #set ($message = $escapetool.xml($services.localization.render('platform.xclass.defaultClassSheet.createPage.pageAlreadyExists', ['__OPEN_LINK__', '__CLOSE_LINK__'])))
          ## First escape the content of the translation, then replace the placeholders with content that would
          ## otherwise be escaped during the first escaping.
          $message.replace('__OPEN_LINK__', $openLink).replace('__CLOSE_LINK__', '&lt;/a&gt;')
        {{/html}}
      {{/warning}}
    #elseif("$!targetDocRef" != '')

      {{warning}}{{translation key="platform.xclass.defaultClassSheet.createPage.denied"/}}{{/warning}}
    #end

    {{html}}
    &lt;form action="$doc.getURL()" id="newdoc" method="post" class="xform half"&gt;
      &lt;fieldset&gt;
      &lt;div class="hidden"&gt;
        &lt;input type="hidden" name="form_token" value="$!{services.csrf.getToken()}" /&gt;
        &lt;input type="hidden" name="parent" value="$escapetool.xml(${defaultParent})"/&gt;
        &lt;input type="hidden" name="template" value="$escapetool.xml(${classTemplateDoc})"/&gt;
        &lt;input type="hidden" name="sheet" value="1"/&gt;
      &lt;/div&gt;
      #locationPicker({
        'id': 'target',
        'title': {
          'label': 'core.create.title',
          'hint': 'core.create.title.hint',
          'name': 'docTitle',
          'placeholder': 'core.create.name.placeholder'
        },
        'preview': {
          'label': 'core.create.locationPreview.label',
          'hint': 'core.create.locationPreview.hint'
        },
        'parent': {
          'label': 'core.create.spaceReference.label',
          'hint': 'core.create.spaceReference.hint',
          'name': 'spaceName',
          'reference': $services.model.resolveSpace($defaultSpace),
          'placeholder': 'core.create.spaceReference.placeholder'
        },
        'name': {
          'label': 'core.create.name.label',
          'hint': 'core.create.name.hint',
          'name': 'docName',
          'placeholder': 'core.create.name.placeholder'
        }
      })
      &lt;p&gt;
        &lt;span class="buttonwrapper"&gt;
          &lt;input type="submit" class="button" value="$escapetool.xml($services.localization.render(
            'platform.xclass.defaultClassSheet.createPage.label'))"/&gt;
        &lt;/span&gt;
      &lt;/p&gt;
      &lt;/fieldset&gt;
    &lt;/form&gt;
    {{/html}}

  #end## has class sheet and class template
  (% id="HExistingPages" %)
  = {{translation key="platform.xclass.defaultClassSheet.pages.heading"/}} =

  {{translation key="platform.xclass.defaultClassSheet.pages.description"/}}

  #set ($options = {
    'className': $doc.fullName,
    'translationPrefix' : 'platform.index.',
    'queryFilters': ['unique']
  })
  {{liveData
    id="classEntries"
    properties="doc.title,doc.location,doc.date,doc.author,doc.objectCount,_actions"
    source="liveTable"
    className="$services.rendering.escape(${doc.fullName}, 'xwiki/2.1')"
    sourceParameters="$services.rendering.escape($escapetool.url($options), 'xwiki/2.1')"
  }}
  {
    "meta": {
      "propertyDescriptors": [
        {
          "id": "doc.title",
          "editable": false
        },
        {
          "id": "doc.objectCount",
          "editable": false,
          "filterable": false,
          "sortable": false
        }
      ]
    }
  }
  {{/liveData}}

  (% id="HClassSheets" %)
  = {{translation key="platform.xclass.defaultClassSheet.sheets.heading"/}} =
  #if (!$hasClassSheets || !$hasClassTemplate)

    {{translation key="platform.xclass.defaultClassSheet.sheets.missing"/}}
  #end

  {{info}}
    #set ($message = $services.localization.render('platform.xclass.defaultClassSheet.sheets.description', ['__START_EM__', '__END_EM__']))
    #set ($message = $escapetool.xml($message))
    ## First escape the content of the translation, then replace the placeholders with content that would
    ## otherwise be escaped during the first escaping.
    {{html}}$message.replace('__START_EM__', '&lt;em&gt;').replace('__END_EM__', '&lt;/em&gt;'){{/html}}
  {{/info}}

  #if(!$hasClassSheets)
    {{html}}
      &lt;form action="$xwiki.getURL($defaultClassSheetReference, 'save', 'editor=wiki')" method="post"&gt;
        &lt;div&gt;
          &lt;input type="hidden" name="form_token" value="$!{services.csrf.getToken()}" /&gt;
          &lt;input type="hidden" name="parent" value="$escapetool.xml(${doc.fullName})"/&gt;
          &lt;input type="hidden" name="xredirect" value="$escapetool.xml(${doc.URL})"/&gt;
          #set ($sheetContent = $xwiki.getDocument('XWiki.ObjectSheet').getContent().replace('XWiki.MyClass',
            $doc.fullName))
          ## We have to encode the new line characters in order to preserve them, otherwise they are replace with a
          ## space when the HTML is cleaned.
          ## FIXME: Use a dedicated escape tool method when XCOMMONS-405 is implemented.
          #set ($sheetContent = $escapetool.xml($sheetContent).replaceAll("\n", '&amp;#10;'))
          &lt;input type="hidden" name="content" value="$sheetContent"/&gt;
          &lt;input type="hidden" name="title" value="${escapetool.h}if(${escapetool.d}doc.documentReference.name == '$escapetool.xml($defaultClassSheetReference.name)')$escapetool.xml($className) Sheet${escapetool.h}{else}${escapetool.d}services.display.title(${escapetool.d}doc, {'displayerHint': 'default', 'outputSyntaxId': 'plain/1.0'})${escapetool.h}end"/&gt;
          &lt;span class="buttonwrapper"&gt;&lt;input type="submit" class="button" value="$escapetool.xml(
            $services.localization.render('platform.xclass.defaultClassSheet.sheets.create'))"/&gt;&lt;/span&gt;
        &lt;/div&gt;
      &lt;/form&gt;
    {{/html}}
  #else
    #set($defaultClassSheetDoc = $xwiki.getDocument($defaultClassSheetReference))
    #if($classSheetReferences.isEmpty() &amp;&amp; !$defaultClassSheetDoc.getObject('XWiki.SheetClass'))
      ## The sheet is not bound to the class.
      #set($xredirect = $xwiki.relativeRequestURL)
      #set($defaultClassSheetStringReference = $services.model.serialize($defaultClassSheetReference, "default"))
      #set($bindURL = $doc.getURL('view', "bindSheet=${escapetool.url($defaultClassSheetStringReference)}&amp;xredirect=${escapetool.url($xredirect)}&amp;form_token=$!{services.csrf.getToken()}"))
      {{warning}}
        {{translation key="platform.xclass.defaultClassSheet.sheets.notBound"/}} ##
        #if ($hasEdit)
          {{html}}
          &lt;a href="$escapetool.xml($bindURL)"&gt;##
            $escapetool.xml($services.localization.render('platform.xclass.defaultClassSheet.sheets.bind')) »##
          &lt;/a&gt;.
          {{/html}}
        #end
      {{/warning}}

    #end
    #if ($classSheetReferences.size() &lt; 2)
      #set($classSheetDoc = $defaultClassSheetDoc)
      #if(!$classSheetReferences.isEmpty())
        #set($classSheetDoc = $xwiki.getDocument($classSheetReferences.get(0)))
      #end
      #set ($sheetPath = "#hierarchy($classSheetDoc.documentReference, {'plain': true, 'local': true, 'limit': 4})")
      #set ($classSheetLink = "$services.localization.render('platform.xclass.defaultClassSheet.sheets.view', [$sheetPath.trim()]) »")
      #set ($classSheetLink = $services.rendering.escape($classSheetLink, 'xwiki/2.1'))
      #set ($classSheetLink = $services.rendering.escape($classSheetLink, 'xwiki/2.1'))
      #set ($classSheetText = ${classSheetDoc.fullName})
      #set ($classSheetText = $services.rendering.escape($classSheetText, 'xwiki/2.1'))
      [[$classSheetLink&gt;&gt;$classSheetText]]
    #else
      {{translation key="platform.xclass.defaultClassSheet.sheets.list"/}}

      #foreach($classSheetReference in $classSheetReferences)
        * [[$services.model.serialize($classSheetReference, "default")]]
      #end
    #end
  #end

  (% id="HClassTemplate" %)
  = {{translation key="platform.xclass.defaultClassSheet.template.heading"/}} =

    {{info}}
      #set ($message = $services.localization.render('platform.xclass.defaultClassSheet.template.description', ['__START_EM__', '__END_EM__']))
      #set ($message = $escapetool.xml($message))
      ## First escape the content of the translation, then replace the placeholders with content that would
      ## otherwise be escaped during the first escaping.
      {{html}}$message.replace('__START_EM__', '&lt;em&gt;').replace('__END_EM__', '&lt;/em&gt;'){{/html}}
    {{/info}}

  #if (!$hasClassTemplate)
    {{html}}
      &lt;form action="$escapetool.xml($classTemplateDoc.getURL('save', 'editor=wiki'))" method="post"&gt;
        &lt;div&gt;
          &lt;input type="hidden" name="form_token" value="$!{services.csrf.getToken()}" /&gt;
          &lt;input type="hidden" name="parent" value="$escapetool.xml(${doc.fullName})"/&gt;
          &lt;input type="hidden" name="xredirect" value="$escapetool.xml(${doc.URL})"/&gt;
          &lt;input type="hidden" name="title" value="$escapetool.xml($className) Template"/&gt;
          &lt;span class="buttonwrapper"&gt;&lt;input type="submit" class="button" value="$escapetool.xml(
            $services.localization.render('platform.xclass.defaultClassSheet.template.create'))"/&gt;&lt;/span&gt;
        &lt;/div&gt;
      &lt;/form&gt;
    {{/html}}
  #else
    #if(!$classTemplateDoc.getObject(${doc.fullName}))
      #set($xredirect = $xwiki.relativeRequestURL)
      #set($createUrl = $classTemplateDoc.getURL('objectadd', "classname=${escapetool.url($doc.fullName)}&amp;xredirect=${escapetool.url($xredirect)}&amp;form_token=$!{services.csrf.getToken()}"))
      {{warning}}
        #set ($message = $services.localization.render('platform.xclass.defaultClassSheet.template.missingObject', ['__CLASS_NAME__']))
        #set ($message = $escapetool.xml($message))
        {{html}}
          ## First escape the content of the translation, then replace the placeholders with content that would
          ## otherwise be escaped during the first escaping.
          $message.replace('__CLASS_NAME__', "&lt;em&gt;$escapetool.xml($className)&lt;/em&gt;")
          &lt;a href="$escapetool.xml($createUrl)"&gt;##
            $escapetool.xml($services.localization.render('platform.xclass.defaultClassSheet.template.addObject', [$className])) »##
          &lt;/a&gt;.
        {{/html}}
      {{/warning}}

    #end
    #set ($templatePath = "#hierarchy($classTemplateDoc.documentReference, {'plain': true, 'local': true, 'limit': 4})")
    #set ($templateDocLink = "$services.localization.render('platform.xclass.defaultClassSheet.template.view', [$templatePath.trim()]) »")
    #set ($templateDocLink = $services.rendering.escape($templateDocLink, 'xwiki/2.1'))
    #set ($templateDocLink = $services.rendering.escape($templateDocLink, 'xwiki/2.1'))
    #set ($templateDocText = "${classTemplateDoc.fullName}")
    ## First escape the xwiki/2.1 syntax of the translation, then replace the placeholders with content that would
    ## otherwise be escaped during the first escaping.
    #set ($templateDocText = $services.rendering.escape($templateDocText, 'xwiki/2.1'))
    [[$templateDocLink&gt;&gt;$templateDocText]]
  #end
  ## Create a template provider only if a template for the current class exists.
  #if ($classTemplateDoc.getObject(${doc.fullName}))
    (% id="HClassTemplateProvider" %)
    = {{translation key="platform.xclass.defaultClassSheet.templateProvider.heading"/}} =

      {{info}}
        #set ($message = $services.localization.render('platform.xclass.defaultClassSheet.templateProvider.description', ['__EM__']))
        #set ($message = $services.rendering.escape($message, 'xwiki/2.1'))
        ## First escape the xwiki/2.1 syntax of the translation, then replace the placeholders with content that would
        ## otherwise be escaped during the first escaping.
        ## The replacement key is itself escaped, and it's escaped form needs to be used for the replacement.
        $message.replace('~_~_~E~M~_~_', '//')
      {{/info}}

    #if (!$hasClassTemplateProvider)
      #set ($templateProviderClassName = 'XWiki.TemplateProviderClass')
      ## Do the page creation and object addition in one step, providing some default values.
      ## In order to get the root space of the class and use it as restrictionSpace, we need to be sure that we have
      ## the expected result for multiple level hierarchies, like MyApplication.Code.MyApplicationClass. In this case,
      ## the template provider in enabled in MyApplication space.
      #set ($restrictionSpace = $doc.documentReference.spaceReferences.get(0).name)
      #set ($createUrlQueryString = $escapetool.url({
        'classname': $templateProviderClassName,
        'xredirect': $xwiki.relativeRequestURL,
        'form_token': $services.csrf.token,
        "${templateProviderClassName}_name": $className,
        "${templateProviderClassName}_description":
          $services.localization.render('platform.xclass.templateProvider.defaultDescription', [$className]),
        "${templateProviderClassName}_template": $classTemplateDoc,
        "${templateProviderClassName}_visibilityRestrictions": $restrictionSpace}))
      #set ($createUrl = $classTemplateProviderDoc.getURL('objectadd', $createUrlQueryString))
      {{html}}
        &lt;form action="$escapetool.xml($classTemplateProviderDoc.getURL('save', 'editor=wiki'))" method="post"&gt;
          &lt;div&gt;
            &lt;input type="hidden" name="form_token" value="$!{services.csrf.getToken()}" /&gt;
            &lt;input type="hidden" name="parent" value="$escapetool.xml(${doc.fullName})"/&gt;
            &lt;input type="hidden" name="xredirect" value="$escapetool.xml($createUrl)"/&gt;
            &lt;input type="hidden" name="title" value="$escapetool.xml($className) Template Provider"/&gt;
            &lt;span class="buttonwrapper"&gt;&lt;input type="submit" class="button" value="$escapetool.xml(
              $services.localization.render('platform.xclass.defaultClassSheet.templateProvider.create'))"/&gt;&lt;/span&gt;
          &lt;/div&gt;
        &lt;/form&gt;
      {{/html}}
    #else
      #set ($templateProviderPath = "#hierarchy($classTemplateProviderDoc.documentReference, {'plain': true, 'local': true, 'limit': 4})")
      #set ($linkTarget = "$services.localization.render('platform.xclass.defaultClassSheet.templateProvider.view', [$templateProviderPath.trim()]) »")
      #set ($linkTarget = $services.rendering.escape($linkTarget, 'xwiki/2.1'))
      #set ($linkTarget = $services.rendering.escape($linkTarget, 'xwiki/2.1'))
      #set ($linkLabel = $services.rendering.escape(${classTemplateProviderDoc.fullName}, 'xwiki/2.1'))
      [[$linkTarget&gt;&gt;$linkLabel]]
    #end
  #end

#end## !$isSheet
{{/velocity}}</content>
  <object>
    <name>XWiki.ClassSheet</name>
    <number>0</number>
    <className>XWiki.SheetDescriptorClass</className>
    <guid>4d854769-efce-441c-8594-349c458b880e</guid>
    <class>
      <name>XWiki.SheetDescriptorClass</name>
      <customClass/>
      <customMapping/>
      <defaultViewSheet/>
      <defaultEditSheet/>
      <defaultWeb/>
      <nameField/>
      <validationScript/>
      <action>
        <customDisplay/>
        <disabled>0</disabled>
        <name>action</name>
        <number>1</number>
        <picker>0</picker>
        <prettyName>Action</prettyName>
        <size>30</size>
        <unmodifiable>0</unmodifiable>
        <validationMessage/>
        <validationRegExp/>
        <classType>com.xpn.xwiki.objects.classes.StringClass</classType>
      </action>
    </class>
    <property>
      <action>view</action>
    </property>
  </object>
</xwikidoc>
