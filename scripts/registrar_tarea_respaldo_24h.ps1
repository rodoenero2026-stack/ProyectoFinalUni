# ============================================================================
# SCRIPT PARA REGISTRAR TAREA PROGRAMADA DE RESPALDO CADA 24 HORAS EN WINDOWS
# Respalda la BD cifrada con AES-256-GCM hacia la unidad USB / Disco Extraíble
# ============================================================================
$TaskName = "Respaldo_24h_SeguridadEnComputo"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$Action = New-ScheduledTaskAction -Execute "node" -Argument "`"$ProjectDir\scripts\backup.js`"" -WorkingDirectory $ProjectDir
$Trigger = New-ScheduledTaskTrigger -Daily -At 12:00PM
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Respaldo automático cada 24 horas cifrado con AES-256-GCM hacia localidad externa USB (Seguridad en Cómputo)" -Force

Write-Host "Tarea programada '$TaskName' registrada exitosamente para ejecutarse cada 24 horas." -ForegroundColor Green
