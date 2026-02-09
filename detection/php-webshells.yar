rule PHP_Command_Execution
{
    meta:
        description = "Detects PHP webshells using common command execution functions"
        author = "Fox Inta"
        
    strings:
        $exec1 = "shell_exec($_GET" nocase
        $exec2 = "system($_GET" nocase
        $exec3 = "exec($_GET" nocase
        $exec4 = "passthru($_GET" nocase
        
    condition:
        any of them
}
