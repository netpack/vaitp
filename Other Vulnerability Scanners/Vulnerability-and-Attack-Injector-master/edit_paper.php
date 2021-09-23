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
<title>PhD edit paper</title>
</head>
<body bgcolor="#ffffff">
<?php
if ($_SESSION['profile']==0)
{
	//********************************************************************************************************
	// Delete Papers
	//********************************************************************************************************
	if(isset($_GET['submit_papers_table_id']) && isset($_GET['submit_papers_table']) && $_GET['submit_papers_table']==Delete)
	{
		$submit_papers_table_id=intval($_GET['submit_papers_table_id']);
		if ($_SESSION['profile']==0) //only users with profile=0 can delete papers
		{
			$conn = phd_connect();
			if(isset($_GET['verify']) && $_GET['verify']==true)
			{
				// execute the query, grab the result in $result
				$sql_text=sprintf("delete from authors where paper=%d",$submit_papers_table_id);
				$result = mysql_query($sql_text,$conn);
				

				$sql_text="delete from papers where id=".$submit_papers_table_id;
				$result = mysql_query($sql_text,$conn);
				
				$sql_text="commit";
				$result = mysql_query($sql_text,$conn);
				
			//	oci_commit($conn);
				echo '<meta http-equiv="REFRESH" content="0; url=show_papers.php">'; //go to the show_papers.php page after deleting the paper
			}
			else
			{
				// execute the MySQL query, grab the result in $result
				$sql_text=sprintf("select title from papers where id=%d",$_GET['submit_papers_table_id']);
				$result = mysql_query($sql_text,$conn);
				
				$row=mysql_fetch_row($result);

				echo "You are about to delete the following paper: <br>\n";
				echo "<b>".htmlspecialchars($_GET['submit_papers_table_id'],ENT_QUOTES)." <-> \"".htmlspecialchars($row[0])."\"</b><br><br>\n";
				echo "Click here to: <a href=".htmlspecialchars($_SERVER['PHP_SELF'])."?submit_papers_table_id=".urlencode(htmlspecialchars($_GET['submit_papers_table_id'],ENT_QUOTES))."&submit_papers_table=Delete&verify=true>delete paper</a><br><br>\n";
				echo "Click here to: <a href='javascript:history.back()'>go back</a>\n";
			}
			mysql_close($conn);
		}
		exit; // does not execute more code
	}
	echo "<p align=center><b>Hello ".htmlspecialchars($_SESSION['user'],ENT_QUOTES)."</b></p>\n";
	echo "<a href=\"logout.php\">Log out</a><br>\n";
	echo "<a href=\"index.php\">home page</a><br>\n";
	echo "<a href=\"insert_paper.php\">Insert paper</a><br>";
	echo "<a href=\"show_papers.php\">Show papers</a><br>";
	echo "<a href='javascript:history.back()'>Back</a>\n";

	//********************************************************************************************************
	// Update Papers
	//********************************************************************************************************
	if (isset($_POST['submit_papers_row']) && $_POST['submit_papers_row']=='Update')
	{
		if ($_SESSION['profile']==0) //only users with profile=0 can update papers
		{
			$conn = phd_connect();

			$year=intval($_POST['year']);
			$relevance=intval($_POST['relevance']);
			$area=intval($_POST['area']);
			$id=intval($_POST['id']);

			// execute the MySQL query, grab the result in $result
			$sql_text=sprintf("update papers set title='%s', link='%s', conference='%s',
			year=%d, resume_por='%s', resume_eng='%s', relevance=%d, area =%d, type ='%s' where id=%d",
			addslashes($_POST['title']),addslashes($_POST['link']),addslashes($_POST['conference']),$year,
			addslashes($_POST['resume_por']),addslashes($_POST['resume_eng']),$relevance,$area,addslashes($_POST['type']),$id);

			$result = mysql_query($sql_text,$conn);
			
			$sql_text="commit";
			$result = mysql_query($sql_text,$conn);
			
		//	oci_commit($conn);
			mysql_close($conn);
		}
		else
		{
			echo "<br><p align=center><b>Sorry, but you are not alowed to edit papers</b></p><br>\n";
		}
	}
	//********************************************************************************************************
	// Insert Papers
	//********************************************************************************************************
	if(isset($_POST['submit_papers_table']) && $_POST['submit_papers_table']=='Insert')
	{
		echo "<br><p align=center><b>Insert Paper</b></p><br>\n";
		$conn = phd_connect();

		$year=intval($_POST['year']);
		$relevance=intval($_POST['relevance']);
		$area=intval($_POST['area']);
		// the next select is to do not let insert two equal rows with the same paper information
		$sql_text=sprintf("select count(*) from papers where title = '%s' and link = '%s'
		and conference ='%s' and year =%s and resume_por ='%s' and resume_eng = '%s'
		and relevance =%d and area =%d and type= '%s'",
		addslashes($_POST['title']),addslashes($_POST['link']),addslashes($_POST['conference']),$year,addslashes($_POST['resume_por']),
		addslashes($_POST['resume_eng']),$relevance,$area,addslashes($_POST['type']));

		$result = mysql_query($sql_text,$conn);
		
		$row=mysql_fetch_row($result);

		//get number of results and do action
		if ($row[0] < 1){
			// execute the query, grab the result in $result
			$sql_text=sprintf("insert into papers (title,link,conference,year,resume_por,resume_eng,relevance,area,type)
			values ('%s','%s','%s',%s,'%s','%s',%d,%d,'%s') ",
			addslashes($_POST['title']),addslashes($_POST['link']),addslashes($_POST['conference']),$year,addslashes($_POST['resume_por']),
			addslashes($_POST['resume_eng']),$relevance,$area,addslashes($_POST['type']));

			$result = mysql_query($sql_text,$conn);
			

			$string = $_POST['authors'];
			$tokens = explode(';', $string);
			
			
			
			
			$papers_id=mysql_insert_id();

			foreach($tokens as $tokens)
			{
				$tokens=trim(ereg_replace(' {2,}', ' ', $tokens)); //to remove extra spaces
				// execute the query, grab the result in $result
				$sql_text=sprintf("insert into authors (paper,name) values (%d,'%s')",$papers_id,addslashes($tokens));
				
				$result = mysql_query($sql_text,$conn);
				
			}
			$sql_text="commit";
			$result = mysql_query($sql_text,$conn);
			
		//	oci_commit($conn);
			$_GET['submit_papers_table_id']=$papers_id;
			$_GET['submit_papers_table']='Edit';

			echo "<br><p align=center><b>Registo inserido com sucesso</b></p><br>\n";
		}
		mysql_close($conn);
	}

	//********************************************************************************************************
	// Edit Paper
	//********************************************************************************************************
	if (isset($_GET['submit_papers_table_id']) && isset($_GET['submit_papers_table']) && $_GET['submit_papers_table']==Edit)
	{
		$submit_papers_table_id=intval($_GET['submit_papers_table_id']);
		echo "<br><p align=center><b>Edit Paper</b></p><br>\n";
		$conn = phd_connect();

		// execute the query, grab the result in $result
		$sql_text=sprintf("select papers.id,title,link,conference,
		year,resume_por,resume_eng,relevance,area,type
		from papers
		where id=%d",$submit_papers_table_id);

		$result = mysql_query($sql_text,$conn);
		
		$row=mysql_fetch_row($result);

		echo "<form action=".htmlspecialchars($_SERVER['PHP_SELF'])."?submit_papers_table_id=".urlencode($_GET['submit_papers_table_id'])."&submit_papers_table=".urlencode($_GET['submit_papers_table'])." method=post>\n";
		?>
		<table border='0' cellspacing='0' cellpadding='0' align=center>
		<tr id='cat'>
		<input type ='hidden' name='id' value='<?php echo htmlspecialchars($row[0],ENT_QUOTES); ?>'>
		<input type ='hidden' name='submit_papers_table' value='<?php echo $_GET['submit_papers_table']; ?>'>
		<input type ='hidden' name='submit_papers_table_id' value=<?php echo $submit_papers_table_id?>>

		<tr> <td bgcolor='#f1f1f1' ><font face='verdana, arial, helvetica' size='2' align='center'>  title
		</font></td> <td bgcolor='#f1f1f1' align='center'><font face='verdana, arial, helvetica' size='2' >
		<input type ='text' class='bginput' name='title' value='<?php echo htmlspecialchars($row[1],ENT_QUOTES); ?>' size="100" maxlength="500"></font></td></tr>

		<tr> <td bgcolor='#ffffff' ><font face='verdana, arial, helvetica' size='2' align='center'>  link
		</font></td> <td bgcolor='#ffffff' align='center'><font face='verdana, arial, helvetica' size='2' >
		<input type ='text' class='bginput' name='link' value='<?php echo htmlspecialchars($row[2],ENT_QUOTES); ?>' size="100" maxlength="500"></font></td></tr>

		<tr> <td bgcolor='#f1f1f1' ><font face='verdana, arial, helvetica' size='2' align='center'>
		<a href=edit_authors.php?id=<?php echo urlencode(htmlspecialchars($row[0],ENT_QUOTES)); ?>>Edit authors</a>

		</font></td> <td bgcolor='#f1f1f1' align='center'><font face='verdana, arial, helvetica' size='2' >
		<input READONLY type ='text' class='bginput' name='year' value='<?php
		//start: List authors
		$sql_text=sprintf("select name from authors where paper=%d",$row[0]);
		$count=1;
		$authors = mysql_query($sql_text,$conn);
		
		while ($row_authors =mysql_fetch_row($authors)) {
			if ($count>1) echo ", ";
			echo htmlspecialchars($row_authors[0],ENT_QUOTES);
			$count++;
		}
		//end: List authors
		?>' size="100" maxlength="100"></font></td></tr>

		<tr> <td bgcolor='#ffffff' ><font face='verdana, arial, helvetica' size='2' align='center'>  conference
		</font></td> <td bgcolor='#ffffff' align='center'><font face='verdana, arial, helvetica' size='2' >
		<input type ='text' class='bginput' name='conference' value='<?php echo htmlspecialchars($row[3],ENT_QUOTES); ?>' size="100" maxlength="500"></font></td></tr>

		<tr> <td bgcolor='#ffffff' ><font face='verdana, arial, helvetica' size='2' align='center'>  year
		</font></td> <td bgcolor='#ffffff' align='center'><font face='verdana, arial, helvetica' size='2' >
		<input type ='text' class='bginput' name='year' value='<?php echo htmlspecialchars($row[4],ENT_QUOTES); ?>' size="6" maxlength="4"></font></td></tr>

		<tr> <td bgcolor='#f1f1f1' ><font face='verdana, arial, helvetica' size='2' align='center'>  resume_por
		</font></td> <td bgcolor='#f1f1f1' align='center'><font face='verdana, arial, helvetica' size='2' >
		<textarea name='resume_por' rows='14' cols='100' maxlength='250'><?php echo htmlspecialchars($row[5],ENT_QUOTES); ?></textarea></font></td></tr>

		<tr> <td bgcolor='#f1f1f1' ><font face='verdana, arial, helvetica' size='2' align='center'>  relevance
		</font></td> <td bgcolor='#f1f1f1' align='center'><font face='verdana, arial, helvetica' size='2' >
		<input type ='text' class='bginput' name='relevance' value='<?php echo htmlspecialchars($row[7],ENT_QUOTES); ?>' size="1" maxlength="2"></font></td></tr>

		<tr> <td bgcolor='#ffffff' ><font face='verdana, arial, helvetica' size='2' align='center'>  area
		</font></td> <td bgcolor='#ffffff' align='center'><font face='verdana, arial, helvetica' size='2' >
		<?php
		//List areas
		$sql_text="select id,name from areas";
		$areas = mysql_query($sql_text,$conn);
		
		echo " <select name='area'>";
		while ($row_areas =mysql_fetch_row($areas)) {
			if($row_areas[0]==$row[8])
			echo "<option value=\"".htmlspecialchars($row_areas[0],ENT_QUOTES)."\" selected>".htmlspecialchars($row_areas[1],ENT_QUOTES)."</option>";
			else
			echo "<option value=\"".htmlspecialchars($row_areas[0],ENT_QUOTES)."\">".htmlspecialchars($row_areas[1],ENT_QUOTES)."</option>";
		}
		echo "</select></font></td></tr>";
		?>

		<tr> <td bgcolor='#f1f1f1' ><font face='verdana, arial, helvetica' size='2' align='center'>  type
		</font></td> <td bgcolor='#f1f1f1' align='center'><font face='verdana, arial, helvetica' size='2' >
		<?php
		//List types
		$sql_text="select id,name from types";
		$types = mysql_query($sql_text,$conn);
		
		echo " <select name='type'>";
		while ($row_types =mysql_fetch_row($types)) {
			if($row_types[0]==htmlspecialchars($row[9]))
			echo "<option value=\"".htmlspecialchars($row_types[0],ENT_QUOTES)."\" selected>".htmlspecialchars($row_types[1],ENT_QUOTES)."</option>";
			else
			echo "<option value=\"".htmlspecialchars($row_types[0],ENT_QUOTES)."\">".htmlspecialchars($row_types[1],ENT_QUOTES)."</option>";
		}
		echo "</select></font></td></tr>";
		?>

		<tr> <td bgcolor='#f1f1f1' colspan='2' align='center'><font face='verdana, arial, helvetica' size='2' align='center'>
		<input type='submit' name='submit_papers_row' value='Update'>
		<input type='reset' value='Reset'>
		</font></td> </tr>

		<tr> <td bgcolor='#f1f1f1' colspan='2' align='center'><font face='verdana, arial, helvetica' size='2' align='center'>
		</font></td> </tr>

		</table></center></form>
		<?php

		?>
		<!-- The data encoding type, enctype, MUST be specified as below -->
		<form enctype="multipart/form-data" action="uploader.php" method="POST">
		<!-- Name of input element determines name in $_FILES array -->
		Send this file: <input name="userfile" type="file" />
		<input type="submit" value="Send File" />
		</form>
		<?php
		// Free the resources associated with the result set
		// This is done automatically at the end of the script
		mysql_close($conn);
	}
}
else
{
	echo "<br><p align=center><b>Sorry, but you are not alowed to upload files</b></p><br>\n";
}
?>
<br>

<br><a href="logout.php">Log out</a>
<br><a href="index.php">home page</a><br>
<a href="insert_paper.php">Insert paper</a><br>
<a href="show_papers.php">Show papers</a><br>
<a href="javascript:history.back()">Back</a>
</body>
</html>
