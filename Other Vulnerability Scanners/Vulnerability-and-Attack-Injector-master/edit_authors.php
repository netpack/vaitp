<?php
//These lines of code should be at the beginnig of every php file
require_once("global.php");  // Define database constants
require_once("library.php"); //function libraries
require_once("session.php"); //session parameters
//The following line must be only in php files that sholud be connected (after the login.php)
require_once("connect.php"); //if the user is not connected then he is sent to the index.php page
?>

<html>
<!--
The following line should be at the beginnig of every php file in order to accept Portugues chars
-->
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<head>
<link rel="shortcut icon" href="favicon.ico">
<title>PhD edit authors</title>
</head>
<body bgcolor="#ffffff">
<?php
echo "<p align=center><b>Hello ".htmlspecialchars($_SESSION['user'],ENT_QUOTES)."</b></p>\n";
echo "<a href=\"logout.php\">Log out</a><br>\n";
echo "<a href=\"index.php\">home page</a><br>\n";
echo "<a href=\"insert_paper.php\">Insert paper</a><br>";
echo "<a href=\"show_papers.php\">Show papers</a><br>";
echo "<a href='javascript:history.back()'>Back</a>\n";
	
//********************************************************************************************************
// Update Authors
//********************************************************************************************************
if (isset($_GET['submit_authors']) && $_GET['submit_authors']=='Update')
{
	$id_author=intval($_GET['id_author']);
	$conn = phd_connect();
	// execute the MySQL query, grab the result in $result
	$sql_text="select paper from authors where id=".$id_author;
	$result = mysql_query($sql_text,$conn);
	
	$row=mysql_fetch_row($result);
	$_GET[id]=$row[0];

	// execute the query, grab the result in $result
	$sql_text="update authors set name='".addslashes($_GET['name'])."' where id=".$id_author;
	$result = mysql_query($sql_text,$conn);
	
	$sql_text="commit";
	$result = mysql_query($sql_text,$conn);
	
//	oci_commit($conn);
	mysql_close($conn);
	echo "<hr>";
	echo "<br>Update executed!<br>";
	echo "<hr>";
}
//********************************************************************************************************
// Delete Authors
//********************************************************************************************************
elseif (isset($_GET['submit_authors']) && $_GET['submit_authors']=='Delete')
{
	$id_author=intval($_GET['id_author']);
	$conn = phd_connect();
	// execute the query, grab the result in $result
	$sql_text="select paper from authors where id=".$id_author;
	$result = mysql_query($sql_text,$conn);
	
	$row=mysql_fetch_row($result);
	$_GET[id]=$row[0];

	// execute the query, grab the result in $result
	$sql_text="delete from  authors where id=".$id_author;
	$result = mysql_query($sql_text,$conn);
	
	$sql_text="commit";
	$result = mysql_query($sql_text,$conn);
	
//	oci_commit($conn);
	mysql_close($conn);
	echo "<hr>";
	echo "<br>delete executed!<br>";
	echo "<hr>";
}
//********************************************************************************************************
// Insert Author
//********************************************************************************************************
elseif (isset($_GET['submit_authors']) && $_GET['submit_authors']=='Insert')
{
	$id=intval($_GET['id']);
	$conn = phd_connect();
	// execute the query, grab the result in $result
	$sql_text="insert into authors (paper,name) values ($id,'".addslashes($_GET['name'])."')";
	$result = mysql_query($sql_text,$conn);
	
	$sql_text="commit";
	$result = mysql_query($sql_text,$conn);
	
//	oci_commit($conn);
	mysql_close($conn);
	echo "<hr>";
	echo "<br>Insert executed!<br>";
	echo "<hr>";
}
//********************************************************************************************************
// Edit Authors
//********************************************************************************************************
{
	if ($_SESSION['profile']==0) //only users with profile=0 can edit authors
	{
		$id=intval($_GET['id']);
		$conn = phd_connect();
		echo "<hr><p align=center><b>Edit Authors</b></p><hr>\n";

		// execute the MySQL query, grab the result in $result
		$sql_text="select* from authors where paper=$id";
		$result = mysql_query($sql_text,$conn);
		
		$column_count = mysql_num_fields($result);

		echo "<table border =1>\n";
		echo "<tr align = center valign=top>\n";
		echo "<th>Edit</th>\n";
		for ($column_num = 0;$column_num<$column_count;$column_num++) {
			$field_name=mysql_field_name($result,$column_num);
			echo "<th>$field_name</th>\n";
		}
		echo "</tr>\n";
		//show table contents
		while ($row =mysql_fetch_row($result)) {
			echo "<tr align = left valign=top>\n";
			echo "<form action='".htmlspecialchars($_SERVER['PHP_SELF'],ENT_QUOTES)."' method=\"get\">\n";
			echo "<TD>\n";
			echo "<input type ='submit' name='submit_authors' value='Update'>\n";
			echo "<input type ='submit' name='submit_authors' value='Delete'>\n";
			echo "<input type='reset' value='Reset'>\n";
			echo "</TD>\n";

			echo "<TD><input READONLY type ='text' class='bginput' name='id_author' value='".htmlspecialchars($row[0],ENT_QUOTES)."' maxlength='50'></TD>\n";
			echo "<TD><input READONLY type ='text' class='bginput' name='paper' value='".htmlspecialchars($row[1],ENT_QUOTES)."' maxlength='50'></TD>\n";
			echo "<TD><input type ='text' class='bginput' name='name' value='".htmlspecialchars($row[2],ENT_QUOTES)."' maxlength='50'></TD>\n";
			echo "</form>\n";
		}
		echo "</tr>\n";
		echo "</table>\n";
		mysql_close($conn);

		echo "<br><b>Insert new author:</b><br>\n";
		echo "<form action='".htmlspecialchars($_SERVER['PHP_SELF'],ENT_QUOTES)."' method=\"get\">\n";
		echo "<input type ='hidden' class='bginput' name='id' value='$id'>\n";
		echo "name: <input type ='text' class='bginput' name='name' maxlength='50'>\n";
		echo "<input type ='submit' name='submit_authors' value='Insert'>\n";
		echo "<input type='reset' value='Reset'>\n";
		echo "</form>\n";
	}
	else
	{
		echo "<br><p align=center><b>Sorry, but you are not alowed to insert new papers</b></p><br>\n";
	}
}

echo "<br>";

echo "<p align=center><b>Hello ".htmlspecialchars($_SESSION['user'],ENT_QUOTES)."</b></p>\n";
echo "<a href=\"logout.php\">Log out</a><br>\n";
echo "<a href=\"index.php\">home page</a><br>\n";
echo "<a href=\"insert_paper.php\">Insert paper</a><br>";
echo "<a href=\"show_papers.php\">Show papers</a><br>";
echo "<a href='javascript:history.back()'>Back</a>\n";
?>
</body>
</html>
