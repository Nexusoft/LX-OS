<?xml version='1.0' encoding="UTF-8"?>
<!-- From GNU and Sun code -->
<xsl:stylesheet version="1.0" xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" xmlns:dr3d="urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0" xmlns:math="http://www.w3.org/1998/Math/MathML" xmlns:form="urn:oasis:names:tc:opendocument:xmlns:form:1.0" xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" exclude-result-prefixes="office meta table number dc fo xlink chart math script xsl draw svg dr3d form text style" office:version="1.0">
<xsl:output method="xml" indent="yes" omit-xml-declaration="no"  />
<xsl:output method="xml" version="1.0" encoding="UTF-8" doctype-public="-//OASIS//DTD DocBook XML V4.1.2//EN" doctype-system="http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd" />


<xsl:key name='headchildren' match="text:p | table:table | text:span | text:list | office:annotation | text:footnote | text:a | text:list-item | draw:plugin | draw:text-box | text:footnote-body | text:section"
   use="generate-id((..|preceding-sibling::text:h[@text:outline-level='1']|preceding-sibling::text:h[@text:outline-level='2']|preceding-sibling::text:h[@text:outline-level='3']|preceding-sibling::text:h[@text:outline-level='4']|preceding-sibling::text:h[@text:outline-level='5'])[last()])"/>

<xsl:key name="children" match="text:h[@text:outline-level &gt; '1' and @text:outline-level &lt; '6']"
  use="generate-id(preceding-sibling::text:h[@text:outline-level &lt; current()/@text:outline-level][1])"/>

<xsl:key name="numberlists"
  match="text:list-style/text:list-level-style-number[@text:level='1' and @text:style-name='Numbering_20_Symbols']"
  use="parent::self/@style:name"/>

<xsl:key name="liststyles" match="text:list-style" use="@style:name"/>

<xsl:template match="/office:document-content">
  <xsl:element name="article">
    <xsl:apply-templates select="office:body/office:text"/>
  </xsl:element>
</xsl:template>

<xsl:template match="office:text">
  <xsl:element name="headchildren">
    <xsl:apply-templates select="key('headchildren', generate-id())"/>
  </xsl:element>
  <xsl:element name="headers">
    <xsl:apply-templates select="text:h[@text:outline-level='1']"/>
    <!--<xsl:apply-templates/>-->
  </xsl:element>
</xsl:template>

<xsl:template match="text:h[@text:outline-level='1']">
  <xsl:choose>
    <xsl:when test=".='Abstract'">
      <abstract>
	<xsl:apply-templates select="key('headchildren', generate-id())"/>
	<xsl:apply-templates select="key('children', generate-id())"/>
      </abstract>
    </xsl:when>
    <xsl:otherwise>
      <xsl:call-template name="make-section">
	<xsl:with-param name="current" select="@text:outline-level"/>
	<xsl:with-param name="prev" select="1"/>
      </xsl:call-template>
      <!--<sect1>
	<title>
	  <xsl:apply-templates/>
	</title>
	<xsl:apply-templates select="key('headchildren', generate-id())"/>
	<xsl:apply-templates select="key('children', generate-id())"/>
      </sect1>-->
    </xsl:otherwise>
  </xsl:choose>

</xsl:template>

<xsl:template match="text:h[@text:outline-level='2'] | text:h[@text:outline-level='3']| text:h[@text:outline-level='4'] | text:h[@text:outline-level='5']">
  <xsl:variable name="level" select="@text:outline-level"></xsl:variable>
  <xsl:call-template name="make-section">
    <xsl:with-param name="current" select="$level"/>
    <xsl:with-param name="prev" select="preceding-sibling::text:h[@text:outline-level &lt; $level][1]/@text:outline-level "/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="make-section">
  <xsl:param name="liststylename"/>
  <xsl:param name="listlevel"/>
  <xsl:param name="current"/>
  <xsl:param name="prev"/>
  <xsl:choose>
    <xsl:when test="$current &gt; $prev+1">
      <xsl:text disable-output-escaping="yes">&lt;sect</xsl:text><xsl:value-of select="$prev +1"/><xsl:text disable-output-escaping="yes">&gt;</xsl:text>
      <title>
      </title>
      <xsl:call-template name="make-section">
	<xsl:with-param name="current" select="$current"/>
	<xsl:with-param name="prev" select="$prev +1"/>
      </xsl:call-template>
      <xsl:text disable-output-escaping="yes">&lt;/sect</xsl:text><xsl:value-of select="$prev +1 "/><xsl:text disable-output-escaping="yes">&gt;</xsl:text>
    </xsl:when>

    <xsl:otherwise>
      <xsl:text disable-output-escaping="yes">&lt;sect</xsl:text><xsl:value-of select="$current"/><xsl:text disable-output-escaping="yes">&gt;</xsl:text>
      <title>
	<xsl:apply-templates/>
      </title>
      <xsl:apply-templates select="key('headchildren', generate-id())"/>
      <xsl:apply-templates select="key('children', generate-id())"/>
      <xsl:text disable-output-escaping="yes">&lt;/sect</xsl:text><xsl:value-of select="$current"/><xsl:text disable-output-escaping="yes">&gt;</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="text:p">
  <xsl:param name="liststylename"/>
  <xsl:param name="listlevel"/>
  <xsl:element name="para">
    <xsl:apply-templates>
      <xsl:with-param name="liststylename" select="$liststylename"/>
      <xsl:with-param name="listlevel" select="$listlevel"/>
    </xsl:apply-templates>
  </xsl:element>
</xsl:template>

<xsl:template match="text:list[@text:style-name]">
  <xsl:param name="liststylename"/>
  <xsl:param name="listlevel"/>
  <xsl:call-template name="make-list">
    <xsl:with-param name="liststylename" select="@text:style-name"/>
    <xsl:with-param name="listlevel" select="1"/>
  </xsl:call-template>
</xsl:template>

<xsl:template match="text:list[not(@text:style-name)]">
  <xsl:param name="liststylename"/>
  <xsl:param name="listlevel"/>
  <xsl:call-template name="make-list">
    <xsl:with-param name="liststylename" select="$liststylename"/>
    <xsl:with-param name="listlevel" select="$listlevel +1"/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="make-list">
  <xsl:param name="liststylename"/>
  <xsl:param name="listlevel"/>
  <xsl:choose>
    <xsl:when test="key('liststyles', $liststylename)/text:list-level-style-number[@text:level=$listlevel]/attribute::text:style-name = 'Numbering_20_Symbols'">
      <xsl:element name="orderedlist">
	<xsl:apply-templates>
	  <xsl:with-param name="liststylename" select="$liststylename"/>
	  <xsl:with-param name="listlevel" select="$listlevel"/>
	</xsl:apply-templates>
      </xsl:element>
    </xsl:when>
    <xsl:otherwise>
      <xsl:element name="itemizedlist">
	<xsl:apply-templates>
	  <xsl:with-param name="liststylename" select="$liststylename"/>
	  <xsl:with-param name="listlevel" select="$listlevel"/>
	</xsl:apply-templates>
      </xsl:element>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="text:list-item">
  <xsl:param name="liststylename"/>
  <xsl:param name="listlevel"/>
  <xsl:element name="listitem">
    <xsl:apply-templates>
      <xsl:with-param name="liststylename" select="$liststylename"/>
      <xsl:with-param name="listlevel" select="$listlevel"/>
    </xsl:apply-templates>
  </xsl:element>
</xsl:template>


<xsl:template match="office:meta"> <!--<xsl:apply-templates/>--> </xsl:template>
<xsl:template match="meta:editing-cycles"> </xsl:template>
<xsl:template match="meta:user-defined"> </xsl:template>
<xsl:template match="meta:editing-duration"> </xsl:template>
<xsl:template match="dc:language"> </xsl:template>

<xsl:template match="dc:date">
	<!--<pubdate>
		<xsl:value-of select="substring-before(.,'T')"/>
	</pubdate>-->
</xsl:template>

<xsl:template match="meta:creation-date"> </xsl:template>

<xsl:template match="office:styles"> <xsl:apply-templates/> </xsl:template>

<xsl:template match="office:script"> </xsl:template>
<xsl:template match="office:settings"> </xsl:template>
<xsl:template match="office:font-decls"> </xsl:template>

<xsl:template match="text:section">
<xsl:choose>
	<xsl:when test="@text:name='ArticleInfo'">
		<articleinfo>
			<title><xsl:value-of select="text:p[@text:style-name='Document Title']"/></title>
			<subtitle><xsl:value-of select="text:p[@text:style-name='Document SubTitle']"/></subtitle>
			<edition><xsl:value-of select="text:p/text:variable-set[@text:name='articleinfo.edition']"/></edition>
			<xsl:for-each select="text:p/text:variable-set[substring-after(@text:name,'articleinfo.releaseinfo')]">
				<releaseinfo>
					<xsl:value-of select="."/>
				</releaseinfo>
			</xsl:for-each>
			<xsl:call-template name="ArticleInfo"><xsl:with-param name="level" select="0"/></xsl:call-template>
	
		</articleinfo>
	</xsl:when>
	<xsl:when test="@text:name='Abstract'">
		<abstract>
			<xsl:apply-templates/>
		</abstract>
	</xsl:when>
	<xsl:when test="@text:name='Appendix'">
		<appendix>
			<xsl:apply-templates/>
		</appendix>
	</xsl:when>
	<xsl:otherwise>
		<xsl:variable name="sectvar"><xsl:text>sect</xsl:text><xsl:value-of select="count(ancestor::text:section)+1"/></xsl:variable>	
		<xsl:variable name="idvar"><xsl:text> id="</xsl:text><xsl:value-of select="@text:name"/><xsl:text>"</xsl:text></xsl:variable>
		<xsl:text disable-output-escaping="yes">&lt;</xsl:text><xsl:value-of select="$sectvar"/><xsl:value-of select="$idvar"/><xsl:text  disable-output-escaping="yes">&gt;</xsl:text>
			<xsl:apply-templates/>
		<xsl:text disable-output-escaping="yes">&lt;/</xsl:text><xsl:value-of select="$sectvar"/><xsl:text  disable-output-escaping="yes">&gt;</xsl:text>
	</xsl:otherwise>


</xsl:choose>
</xsl:template>

<xsl:template name="ArticleInfo">
	<xsl:param name="level"/>
	<xsl:variable name="author"><xsl:value-of select="concat('articleinfo.author_','', $level)"/></xsl:variable>
	<xsl:if test="text:p/text:variable-set[contains(@text:name, $author )]">
		<xsl:call-template name="Author"><xsl:with-param name="AuthorLevel" select="0"/></xsl:call-template>
		<xsl:call-template name="Copyright"><xsl:with-param name="CopyrightLevel" select="0"/></xsl:call-template>	
	</xsl:if>	
</xsl:template>

<xsl:template name="Copyright">
	<xsl:param name="CopyrightLevel"/>
	
	<xsl:variable name="Copyright"><xsl:value-of select="concat('articleinfo.copyright_','', $CopyrightLevel)"/></xsl:variable>
	
	<xsl:if test="text:p/text:variable-set[contains(@text:name,$Copyright)]">
		<copyright>
			<xsl:call-template name="Year">
				<xsl:with-param name="CopyrightLevel" select="$CopyrightLevel"/>
				<xsl:with-param name="YearlLevel" select="0"/>
			</xsl:call-template>
			<xsl:call-template name="Holder">
				<xsl:with-param name="CopyrightLevel" select="$CopyrightLevel"/>
				<xsl:with-param name="HolderlLevel" select="0"/>

			</xsl:call-template>
		</copyright>
	</xsl:if>
</xsl:template>


<xsl:template name="Year">
	<xsl:param name="CopyrightLevel"/>
	<xsl:param name="YearLevel"/>
	<xsl:variable name="Copyright"><xsl:value-of select="concat('articleinfo.copyright_','', $CopyrightLevel)"/></xsl:variable>
<xsl:variable name="Year"><xsl:value-of select="concat($Copyright,'',concat('.year_','',$YearLevel))"/></xsl:variable>

	<xsl:if test="text:p/text:variable-set[@text:name=$Year]">
		<orgname>
			<xsl:value-of select="text:p/text:variable-set[@text:name=$Year]"/>
		</orgname>
	</xsl:if>
</xsl:template>


<xsl:template name="Holder">
	<xsl:param name="CopyrightLevel"/>
	<xsl:param name="HolderLevel"/>
	<xsl:variable name="Copyright"><xsl:value-of select="concat('articleinfo.copyright_','', $CopyrightLevel)"/></xsl:variable>
<xsl:variable name="Holder"><xsl:value-of select="concat($Copyright,'',concat('.holder_','',$HolderLevel))"/></xsl:variable>

	<xsl:if test="text:p/text:variable-set[@text:name=$Holder]">
		<orgname>
			<xsl:value-of select="text:p/text:variable-set[@text:name=$Holder]"/>
		</orgname>
	</xsl:if>
</xsl:template>



<xsl:template name="Author">
	<xsl:param name="AuthorLevel"/>
	<xsl:variable name="Author"><xsl:value-of select="concat('articleinfo.author_','', $AuthorLevel)"/></xsl:variable>	
	<xsl:if test="text:p/text:variable-set[contains(@text:name, $Author )]">
		<author>
			<xsl:call-template name="Surname"><xsl:with-param name="AuthorLevel" select="$AuthorLevel"/><xsl:with-param name="SurnameLevel" select="0"/></xsl:call-template>
			<xsl:call-template name="Firstname"><xsl:with-param name="AuthorLevel" select="$AuthorLevel"/><xsl:with-param name="FirstnameLevel" select="0"/></xsl:call-template>
			<xsl:call-template name="Affiliation"><xsl:with-param name="AuthorLevel" select="$AuthorLevel"/><xsl:with-param name="AffilLevel" select="0"/></xsl:call-template>
		</author>
		<xsl:call-template name="Author"><xsl:with-param name="AuthorLevel" select="$AuthorLevel+1"/></xsl:call-template>
	</xsl:if>	
</xsl:template>


<xsl:template name="Surname">
	<xsl:param name="AuthorLevel"/>
	<xsl:param name="SurnameLevel"/>
	<xsl:variable name="Author"><xsl:value-of select="concat('articleinfo.author_','', $AuthorLevel)"/></xsl:variable>
	<xsl:variable name="Surname"><xsl:value-of select="concat($Author,'',concat('.surname_','',$SurnameLevel))"/></xsl:variable>
	<xsl:if test="text:p/text:variable-set[@text:name=$Surname]">
		<surname>
			<xsl:value-of select="text:p/text:variable-set[@text:name=$Surname]"/>
		</surname>
		<xsl:call-template name="Surname"><xsl:with-param name="AuthorLevel" select="$AuthorLevel"/>
		<xsl:with-param name="SurnameLevel" select="SurnameLevel+1"/>
		</xsl:call-template>

	</xsl:if>
</xsl:template>




<xsl:template name="Firstname">
	<xsl:param name="AuthorLevel"/>
	<xsl:param name="FirstnameLevel"/>
	<xsl:variable name="Author"><xsl:value-of select="concat('articleinfo.author_','', $AuthorLevel)"/></xsl:variable>
	<xsl:variable name="Firstname"><xsl:value-of select="concat($Author,'',concat('.firstname_','',$FirstnameLevel))"/></xsl:variable>
	<xsl:if test="text:p/text:variable-set[@text:name=$Firstname]">
		<firstname>
			<xsl:value-of select="text:p/text:variable-set[@text:name=$Firstname]"/>
		</firstname>
		<xsl:call-template name="Surname">
			<xsl:with-param name="AuthorLevel" select="$AuthorLevel"/>
			<xsl:with-param name="FirstnameLevel" select="FirstnameLevel+1"/>
		</xsl:call-template>
	</xsl:if>
</xsl:template>



<xsl:template name="Affiliation">
	<xsl:param name="AuthorLevel"/>
	<xsl:param name="AffilLevel"/>
	<xsl:variable name="Author"><xsl:value-of select="concat('articleinfo.author_','', $AuthorLevel)"/></xsl:variable>
	<xsl:variable name="Affil"><xsl:value-of select="concat($Author,'',concat('.affiliation_','',$AffilLevel))"/></xsl:variable>
	<xsl:if test="text:p/text:variable-set[contains(@text:name,$Affil)]">
		<affiliation>
			<xsl:call-template name="Orgname">
				<xsl:with-param name="AuthorLevel" select="$AuthorLevel"/>
				<xsl:with-param name="AffilLevel" select="$AffilLevel"/><xsl:with-param name="OrgLevel" select="0"/>
			</xsl:call-template>
			<xsl:call-template name="Address">
				<xsl:with-param name="AuthorLevel" select="$AuthorLevel"/>
				<xsl:with-param name="AffilLevel" select="$AffilLevel"/><xsl:with-param name="AddressLevel" select="0"/>

			</xsl:call-template>
		</affiliation>
	</xsl:if>
</xsl:template>

<xsl:template name="Orgname">
	<xsl:param name="AuthorLevel"/>
	<xsl:param name="AffilLevel"/>
	<xsl:param name="OrgLevel"/>

	<xsl:variable name="Author"><xsl:value-of select="concat('articleinfo.author_','', $AuthorLevel)"/></xsl:variable>
<xsl:variable name="Affil"><xsl:value-of select="concat($Author,'',concat('.affiliation_','',$AffilLevel))"/></xsl:variable>
	<xsl:variable name="Org"><xsl:value-of select="concat($Affil,'',concat('.orgname_','',$OrgLevel))"/></xsl:variable>

	<xsl:if test="text:p/text:variable-set[@text:name=$Org]">
		<orgname>
			<xsl:value-of select="text:p/text:variable-set[@text:name=$Org]"/>
		</orgname>
	</xsl:if>
</xsl:template>

<xsl:template name="Address">
	<xsl:param name="AuthorLevel"/>
	<xsl:param name="AffilLevel"/>
	<xsl:param name="AddressLevel"/>

	<xsl:variable name="Author"><xsl:value-of select="concat('articleinfo.author_','', $AuthorLevel)"/></xsl:variable>
<xsl:variable name="Affil"><xsl:value-of select="concat($Author,'',concat('.affiliation_','',$AffilLevel))"/></xsl:variable>
	<xsl:variable name="Address"><xsl:value-of select="concat($Affil,'',concat('.address_','',$AddressLevel))"/></xsl:variable>

	<xsl:if test="text:p/text:variable-set[@text:name=$Address]">
		<address>
			<xsl:value-of select="text:p/text:variable-set[@text:name=$Address]"/>
		</address>
	</xsl:if>
</xsl:template>

<xsl:template match="text:p[@text:style-name='Document Title']">
</xsl:template>

<xsl:template match="text:p[@text:style-name='Document SubTitle']">
</xsl:template>

<xsl:template match="text:p[@text:style-name='Section Title']">
	<xsl:element name="title">
		<xsl:apply-templates/>
	</xsl:element>
</xsl:template>

<xsl:template match="text:p[@text:style-name='Appendix Title']">
	<xsl:element name="title">
		<xsl:apply-templates/>
	</xsl:element>
</xsl:template>


<!--<xsl:template match="text:p[@text:style-name='VarList Item']">
	<xsl:if test="not(preceding-sibling::text:p[@text:style-name='VarList Item'])">
		<xsl:text disable-output-escaping="yes">&lt;listitem&gt;</xsl:text>
	</xsl:if>
		<para>
			<xsl:apply-templates/>
		</para>
	<xsl:if test="not(following-sibling::text:p[@text:style-name='VarList Item'])">
		<xsl:text disable-output-escaping="yes">&lt;/listitem&gt;</xsl:text>
	</xsl:if>
</xsl:template>-->

<xsl:template match="text:p[@text:style-name='VarList Term']">
	<xsl:element name="term">
			<xsl:apply-templates/>
	</xsl:element>
</xsl:template>

<xsl:template match="text:p[@text:style-name='VarList Item']">
	<xsl:element name="listitem">
		<xsl:element name="para">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:element>
</xsl:template>

<xsl:template match="text:p[@text:style-name='Section1 Title']">
	<xsl:element name="title">
		<xsl:apply-templates/>
	</xsl:element>
</xsl:template>


<xsl:template match="text:p[@text:style-name='Section2 Title']">
	<xsl:element name="title">
		<xsl:apply-templates/>
	</xsl:element>
</xsl:template>


<xsl:template match="text:p[@text:style-name='Section3 Title']">
	<xsl:element name="title">
		<xsl:apply-templates/>
	</xsl:element>
</xsl:template>

<xsl:template match="text:footnote-citation">
</xsl:template>

<xsl:template match="text:p[@text:style-name='Mediaobject']">
	<mediaobject>
		<xsl:apply-templates/>
	</mediaobject>
</xsl:template>

<xsl:template match="office:annotation/text:p">
	<note>
	<remark>
		<xsl:apply-templates/>
	</remark>
	</note>
</xsl:template>

<!--<xsl:template match="meta:initial-creator">
	<author>
	<xsl:apply-templates />
		</author>
</xsl:template>-->

<xsl:template match="table:table"> 
	<xsl:choose>
		<xsl:when test="following-sibling::text:p[@text:style-name='Table']">
			<table frame="all">
				 <xsl:attribute name="id">
					<xsl:value-of select="@table:name"/>
				</xsl:attribute>
				<title>
					<xsl:value-of select="following-sibling::text:p[@text:style-name='Table']"/>
				</title>
				<xsl:call-template name="generictable"/>
			</table>
		</xsl:when>
		<xsl:otherwise>
			<informaltable frame="all">
				<xsl:call-template name="generictable"/>
			</informaltable>
		</xsl:otherwise>
	</xsl:choose>
</xsl:template>


<xsl:template name="generictable">
			<xsl:variable name="cells" select="count(descendant::table:table-cell)" ></xsl:variable>
			<xsl:variable name="rows"><xsl:value-of select="count(descendant::table:table-row) "/></xsl:variable>
			<xsl:variable name="cols"><xsl:value-of select="$cells div $rows"/></xsl:variable>
			<xsl:variable name="numcols">
			<xsl:choose>
					<xsl:when test="child::table:table-column/@table:number-columns-repeated">
							<xsl:value-of select="number(table:table-column/@table:number-columns-repeated+1)"/>
					</xsl:when>
					<xsl:otherwise >
							<xsl:value-of select="$cols"/>
					</xsl:otherwise>
			</xsl:choose>
		</xsl:variable>
		<xsl:element name="tgroup">
			<xsl:attribute name="cols">
						<xsl:value-of select="$numcols"/>
			</xsl:attribute>	
			<xsl:call-template name="colspec"><xsl:with-param name="left" select="1" /></xsl:call-template>
				<xsl:apply-templates/>
		</xsl:element>
</xsl:template>



<xsl:template name="colspec">
	<xsl:param name="left"/>
	<xsl:if test="number($left &lt; ( table:table-column/@table:number-columns-repeated +2)  )">
			<xsl:element name="colspec">
				<xsl:attribute name="colnum"><xsl:value-of select="$left"/></xsl:attribute>
				<xsl:attribute name="colname">c<xsl:value-of select="$left"/></xsl:attribute>
			</xsl:element>
			<xsl:call-template name="colspec"><xsl:with-param name="left" select="$left+1" /></xsl:call-template>
	</xsl:if>
</xsl:template>



<xsl:template match="table:table-column">
		<xsl:apply-templates/>
</xsl:template>

<xsl:template match="table:table-header-rows">
	<thead>
		<xsl:apply-templates/>
	</thead>	
</xsl:template>

<xsl:template match="table:table-header-rows/table:table-row">
	<row>
		<xsl:apply-templates />
	</row>
</xsl:template>

<xsl:template match="table:table/table:table-row">
	<xsl:if test="not(preceding-sibling::table:table-row)">
		<xsl:text disable-output-escaping="yes">&lt;tbody&gt;</xsl:text>
	</xsl:if>
	<row>
		<xsl:apply-templates />
	</row>
		<xsl:if test="not(following-sibling::table:table-row)">
		<xsl:text disable-output-escaping="yes">&lt;/tbody&gt;</xsl:text>
	</xsl:if>
</xsl:template>

<xsl:template match="table:table-cell">
 <xsl:element name="entry">
 		<xsl:if test="@table:number-columns-spanned >'1'">
			<xsl:attribute name="namest"><xsl:value-of select="concat('c',count(preceding-sibling::table:table-cell[not(@table:number-columns-spanned)]) +sum(preceding-sibling::table:table-cell/@table:number-columns-spanned)+1)"/></xsl:attribute>
			<xsl:attribute name="nameend"><xsl:value-of select="concat('c',count(preceding-sibling::table:table-cell[not(@table:number-columns-spanned)]) +sum(preceding-sibling::table:table-cell/@table:number-columns-spanned)+ @table:number-columns-spanned)"/></xsl:attribute>
		</xsl:if>
		<xsl:apply-templates />
	</xsl:element>
</xsl:template>

<xsl:template match="text:p">
<xsl:param name="liststylename"/>
<xsl:param name="listlevel"/>
<xsl:choose>
	<xsl:when test="@text:style-name='Table'">
	</xsl:when>
	<xsl:otherwise>
		<para>		
			<xsl:apply-templates/>
		</para>
	</xsl:otherwise>
</xsl:choose>
</xsl:template>


<xsl:template match="dc:title">
</xsl:template>

<xsl:template match="dc:description">
	<abstract><para>
		<xsl:apply-templates/>
		</para>
	</abstract>
</xsl:template>

<xsl:template match="dc:subject">
</xsl:template>


<xsl:template match="meta:generator">
</xsl:template>

<xsl:template match="draw:plugin">
<xsl:element name="audioobject">
	<xsl:attribute name="fileref">
		<xsl:value-of select="@xlink:href"/>
	</xsl:attribute>
	<xsl:attribute name="width">
	</xsl:attribute>
</xsl:element>
</xsl:template>

<xsl:template match="text:footnote">
	<footnote>
		<xsl:apply-templates/>
	</footnote>
</xsl:template>

<xsl:template match="text:footnote-body">
		<xsl:apply-templates/>
</xsl:template>


<xsl:template match="draw:text-box">
</xsl:template>



<xsl:template match="draw:image">
<xsl:choose>
	<xsl:when test="parent::text:p[@text:style-name='Mediaobject']">
		<xsl:element name="imageobject">
			<xsl:element name="imagedata">
			<xsl:attribute name="fileref">
				<xsl:value-of select="@xlink:href"/>
			</xsl:attribute>
			</xsl:element>
			<xsl:element name="caption">
				<xsl:value-of select="."/>
			</xsl:element>
		</xsl:element>
	</xsl:when>
	<xsl:otherwise>
		<xsl:element name="inlinegraphic">
			<xsl:attribute name="fileref">
				<xsl:value-of select="@xlink:href"/>
			</xsl:attribute>
			<xsl:attribute name="width"></xsl:attribute>
		</xsl:element>
	</xsl:otherwise>
</xsl:choose>
</xsl:template>





<xsl:template match="text:span">
<xsl:choose>
<xsl:when test="./@text:style-name='GuiMenu'">
		<xsl:element name="guimenu">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="./@text:style-name='GuiSubMenu'">
		<xsl:element name="guisubmenu">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
		<xsl:when test="@text:style-name='GuiMenuItem'">
		<xsl:element name="guimenuitem">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='GuiButton'">
		<xsl:element name="guibutton">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
		<xsl:when test="@text:style-name='GuiButton'">
		<xsl:element name="guibutton">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='GuiLabel'">
		<xsl:element name="guilabel">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='Emphasis'">
		<xsl:element name="emphasis">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='FileName'">
		<xsl:element name="filename">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='Application'">
		<xsl:element name="application">
			<xsl:value-of select="."/>	
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='Command'">
		<command>
			<xsl:apply-templates/>
		</command>
	</xsl:when>
	<xsl:when test="@text:style-name='SubScript'">
		<subscript>
			<xsl:apply-templates/>
		</subscript>
	</xsl:when>
	<xsl:when test="@text:style-name='SuperScript'">
		<superscript>
			<xsl:apply-templates/>
		</superscript>
	</xsl:when>
	<xsl:when test="@text:style-name='SystemItem'">
		<systemitem>
			<xsl:apply-templates/>
		</systemitem>
	</xsl:when>
	<xsl:when test="@text:style-name='ComputerOutput'">
		<computeroutput>
			<xsl:apply-templates/>
		</computeroutput>
	</xsl:when>
	<xsl:when test="@text:style-name='Highlight'">
		<highlight>
			<xsl:apply-templates/>
		</highlight>
	</xsl:when>
		<xsl:when test="@text:style-name='KeyCap'">
		<keycap>
			<xsl:apply-templates/>
		</keycap>
	</xsl:when>
	<xsl:when test="@text:style-name='KeySym'">
		<xsl:element name="keysym">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:when>
	<xsl:when test="@text:style-name='KeyCombo'">
		<keycombo>
			<xsl:apply-templates/>
		</keycombo>
	</xsl:when>
	<xsl:otherwise>
		<xsl:apply-templates/>
	</xsl:otherwise>
</xsl:choose>
	
</xsl:template>


<xsl:template match="text:a">
	<xsl:choose>
		<xsl:when test="contains(@xlink:href,'://')">
			<xsl:element name="ulink">
				<xsl:attribute name="url">
					<xsl:value-of select="@xlink:href"/>
				</xsl:attribute>
				<xsl:apply-templates/>
			</xsl:element>
		</xsl:when>
		<xsl:when test="contains(@xlink:href,'mailto:')"> 
	        <xsl:element name="ulink">
                <xsl:attribute name ="url"> 
    	            <xsl:value-of select="@xlink:href"/> 
                </xsl:attribute>
                <xsl:apply-templates/>
            </xsl:element> 
        </xsl:when> 
		<xsl:when test="not(contains(@xlink:href,'#'))">
			<xsl:element name="olink">
				<xsl:attribute name="targetdocent">
					<xsl:value-of select="@xlink:href"/>
				</xsl:attribute>
				<xsl:apply-templates/>
			</xsl:element>
		</xsl:when>
		<xsl:otherwise>
		<xsl:variable name="linkvar" select="substring-after(@xlink:href,'#')"/>
			<xsl:element name="link">
				<xsl:attribute name="linkend">
					<xsl:value-of select="substring-before($linkvar,'%')"/>	
				</xsl:attribute>
				<xsl:apply-templates/>
			</xsl:element>
		</xsl:otherwise>
	</xsl:choose>
</xsl:template>


</xsl:stylesheet>
