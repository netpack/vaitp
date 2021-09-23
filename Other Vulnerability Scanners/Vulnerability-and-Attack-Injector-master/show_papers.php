<?php
//These lines of code should be at the beginnig of every php file
require_once("global.php");  // Define database constants
require_once("library.php"); //function libraries
require_once("session.php"); //session parameters
//The following line must be only in php files that sholud be connected (after the login.php)
require_once("connect.php"); //if the user is not connected then he is sent to the index.php page
?>

<html>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<head>
<link rel="shortcut icon" href="favicon.ico">
<title>PhD paper reviews</title>
</head>
<body bgcolor="#ffffff">

<?php
//function to calculate the execution time
function exec_time()
{
	$mtime = explode(" ", microtime());
	$msec = (double)$mtime[0];
	$sec = (double)$mtime[1];
	return $sec + $msec;
}
?>

<?php

//********************************************************************************************************
// Inital screen
//********************************************************************************************************

{
	echo "<p align=center><b>Hello ".$_SESSION['user']."</b></p>";
	echo "<a href=\"logout.php\">Log out</a><br>";
	echo "<a href=\"index.php\">home page</a><br>";
	echo "<a href=\"insert_paper.php\">Insert paper</a><br>";
	echo "<a href='javascript:history.back()'>Back</a>\n";

	$start=(isset($_GET['start']) && $_GET['start']!='' && is_numeric($_GET['start']))? $_GET['start'] : 0; // This variable is set to zero for the first page

	$start=$_GET['start'];
	if(!isset($start)) {                         // This variable is set to 0 for the first page
		$start = 0;
	}

	$limit = 5;                                 // Number of records to be shown per page.

	$eu = ($start - 0);
	$thiss = $eu + $limit;
	$back = $eu - $limit;
	$next = $eu + $limit;

	$search_column=htmlspecialchars($_GET['search_column'],ENT_QUOTES);
	if(!isset($search_column)) {                         // This variable is set to '' for the first page
		$search_column = '';
	}

	$search_value=htmlspecialchars($_GET['search_value'],ENT_QUOTES);
	if(!isset($search_value)) {                         // This variable is set to '' for the first page
		$search_value = '';
	}

	$search_string='';
	if ($search_column=='title') $search_string=" and upper(title) like upper('%$search_value%')";
	if ($search_column=='authors') $search_string=" and upper(auth.name) like upper('%$search_value%')";
	if ($search_column=='conference') $search_string=" and upper(conference) like upper('%$search_value%')";
	if ($search_column=='year') $search_string=" and year = '$search_value'";
	if ($search_column=='resume_por') $search_string=" and upper(resume_por) like upper('%$search_value%')";
	if ($search_column=='relev') $search_string=" and upper(relevance) like upper('%$search_value%')";

	//start measuring the start time 
	$start_db_call = exec_time();

	$conn = phd_connect();

	// execute the query, grab the result in $result
	$sql_text="select '' as id,'' as title,'' as link,'' as authors,'' as conference,
	'' as year,'' as resume_por,'' as resume_eng,'' as relev,'' as area,'' as type
	from dual";

	$result =mysql_query($sql_text,$conn);
	
	
	$sort_by=$_GET['sort_by'];
	if(!isset($sort_by) || $sort_by=='') {                         // This variable is set to 'id' for the first page
		$sort_by = 'id';
	}
	$asc_desc=$_GET['asc_desc'];
	if(!isset($asc_desc) || $asc_desc=='') {                         // This variable is set to 'desc' for the first page
		$asc_desc='desc';
	}
	if ($asc_desc!='asc') {$asc_desc='desc';}

	echo "<form action='".htmlspecialchars($_SERVER['PHP_SELF'],ENT_QUOTES)."' method=\"get\">";
	
	//show the combo box for the sort column
	echo " <td>Sort by: <select name='sort_by'>";
	$column_count = mysql_num_fields($result);
	$test_sort_by=-1;
	for ($column_num = 0;$column_num<$column_count;$column_num++) {
		$field_name=mysql_field_name($result,$column_num);
		if($field_name==$sort_by) {
			$test_sort_by=0;
			echo "<option value=\"$field_name\" selected>$field_name</option>";
		}
		else echo "<option value=\"$field_name\">$field_name</option>";
	}
	echo "</select>";
	if($test_sort_by==-1) {                         // This variable is set to 'ID' for the first page
		$sort_by = 'ID';
	}
	
	//show the combo box for the asc_desc column
	echo "<select name='asc_desc'>";
	if($asc_desc=='desc') {
		echo "<option value=\"desc\" selected>desc</option>";
		echo "<option value=\"asc\">asc</option>";
	} else {
		echo "<option value=\"desc\" >desc</option>";
		echo "<option value=\"asc\" selected>asc</option>";
	}
	echo "</select>";

	//show the combo box for the search column
	echo "<br>Search by: <select name='search_column'";
	echo "<option value=\"none\"";
	if($search_column=='none'){
		echo " selected ";
		$search_value='';
	}
	echo ">none</option>";
	echo "<option value=\"title\"";
	if($search_column=='title') echo " selected ";
	echo ">title</option>";
	echo "<option value=\"authors\"";
	if($search_column=='authors') echo " selected ";
	echo ">authors</option>";
	echo "<option value=\"conference\"";
	if($search_column=='conference') echo " selected ";
	echo ">conference</option>";
	echo "<option value=\"year\"";
	if($search_column=='year') echo " selected ";
	echo ">year</option>";
	echo "<option value=\"resume_por\"";
	if($search_column=='resume_por') echo " selected ";
	echo ">resume_por</option>";
	echo "<option value=\"relev\"";
	if($search_column=='relev') echo " selected ";
	echo ">relev</option>";
	echo "</select>";
	echo "<input type ='text' class='bginput' value=\"".$search_value."\" name='search_value' maxlength='500' size='50'>";
	echo "<br><input type='submit' value='Go!'>";
	echo "<input type='reset' value='Reset'>";
	echo "<br>";
	echo "</form>";

	$sql_text=sprintf("select count(distinct papers.id)
	from papers left outer join authors auth on (auth.paper=papers.id),areas,types
	where papers.area=areas.id and papers.type=types.id
	%s",$search_string);

	$result = mysql_query($sql_text,$conn);
	
	$row = mysql_fetch_row($result);
	$nume=$row[0];

	//executing the Oracle query grabing only 5 records at a time 
	$sql_text=sprintf("select distinct papers.id,title,link,'' as authors,conference,
	year,resume_por,relevance relev,areas.name area,types.name type
	from papers left outer join authors as auth on (auth.paper=papers.id),areas,types
	where papers.area=areas.id and papers.type=types.id
	%s
	order by '%s' %s
	limit %d, %d",$search_string,$sort_by,$asc_desc,$eu,$limit);
	

	$result = mysql_query($sql_text,$conn);
	
	echo "<hr>";
	echo "<h3>We got ".$nume." records matching your query</h3>";
	//show columns names
	$column_count = mysql_num_fields($result);

	// form with the papers information
	echo "<table border =1>";
	echo '<tr align = center valign=top>';
	echo "<th>sel.</th>";
	for ($column_num = 0;$column_num<$column_count;$column_num++) {
		$field_name=mysql_field_name($result,$column_num);
		echo "<th>$field_name</th>";
	}
	echo "</tr>";
	//start: show table contents
	while ($row =mysql_fetch_row($result)) {
		if($bgcolor=='#f1f1f1'){$bgcolor='#ffffff';}
		else{$bgcolor='#f1f1f1';}
		echo '<tr align = left valign=top>';
		echo "<td bgcolor=$bgcolor align=center>\n";
		if ($_SESSION['profile']==0)
		{
			echo "<a href=edit_paper.php?submit_papers_table_id=".urlencode($row[0])."&submit_papers_table=Edit>Edit</a><br><br>\n";
			echo "<a href=edit_paper.php?submit_papers_table_id=".urlencode($row[0])."&submit_papers_table=Delete>Delete</a>\n";
		}
		echo "</td>";
		for ($column_num = 0;$column_num<$column_count;$column_num++){
			if (mysql_field_name($result,$column_num)=='link')
			echo "<td bgcolor=$bgcolor><a href=\"downloader.php?file=".urlencode($row[$column_num])."\">...</a></td>";
			elseif (mysql_field_name($result,$column_num)=='authors') {
				echo "<td bgcolor=$bgcolor>";
				//start: List authors
				$sql_text="select name from authors where paper=$row[0]";
				$count=1;
				$authors = mysql_query($sql_text,$conn);
   			
				while ($row_authors = mysql_fetch_row($authors)) {
					if ($count>1) echo ", ";
					echo htmlspecialchars($row_authors[0],ENT_QUOTES);
					$count++;
				}
				//end: List authors
				echo "</td>";
			}
			else {
				if (trim($row[$column_num])!="")	// if column is empty put a space for td border
				echo "<TD bgcolor=$bgcolor align=\"left\">".htmlspecialchars($row[$column_num],ENT_QUOTES)."</TD>";
				else echo "<TD bgcolor=$bgcolor align=\"left\"> &nbsp;</TD>";
			}
		}
		echo '</tr>';
	}
	//end: show table contents
	echo "</table>";

	////////////////////////////// End of displaying the table with records ////////////////////////

	/////////////// Start the buttom links with Prev and next link with page numbers /////////////////
	echo "<table align = 'center' width='50%'><tr><td  align='left' width='30%'>";

	//// if our variable $back is equal to 0 or more then only we will display the link to move back ////////
	if($back >=0) {
		print "<a href='$page_name?start=$back&sort_by=$sort_by&asc_desc=$asc_desc&search_column=$search_column&search_value=$search_value'><font face='Verdana' size='2'>PREV</font></a>"; 
	}
	//////////////// Let us display the page links at  center. We will not display the current page as a link ///////////
	echo "</td><td align=center width='30%'>";
	$i=0;
	$l=1;
	for($i=0;$i < $nume;$i=$i+$limit){
		if($i <> $eu){
			echo " <a href='$page_name?start=$i&sort_by=$sort_by&asc_desc=$asc_desc&search_column=$search_column&search_value=$search_value'><font face='Verdana' size='2'>$l</font></a> ";
		}
		else { echo "<font face='Verdana' size='4' color=red>$l</font>";}        /// Current page is not displayed as link and given font color red
		$l=$l+1;
	}


	echo "</td><td  align='right' width='30%'>";
	///////////// If we are not in the last page then Next link will be displayed. Here we check that /////
	if($thiss < $nume) {
		print "<a href='$page_name?start=$next&sort_by=$sort_by&asc_desc=$asc_desc&search_column=$search_column&search_value=$search_value'><font face='Verdana' size='2'>NEXT</font></a>";} 
		echo "</td></tr></table>";

		// we are all done, so close the MySQL connection
		mysql_close($conn);
		$end_db_call = exec_time();
		$runtime = $end_db_call - $start_db_call;
		echo "<br>";
		echo "Database call and echo took $runtime seconds";
	}
	?>
	<br>

	<br><a href="logout.php">Log out</a>
	<br><a href="index.php">home page</a><br>
	<a href="insert_paper.php">Insert paper</a><br>
	<a href='javascript:history.back()'>Back</a>
	<?php
	?>
</body>
</html>
