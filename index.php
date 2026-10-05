<?php
declare(strict_types=1);
const DATA_FILE=__DIR__.'/masks.json';
const HTACCESS_FILE=__DIR__.'/.htaccess';
const MAX_REQUEST_SIZE=2097152;
ini_set('display_errors','0');
ini_set('session.use_strict_mode','1');
ini_set('session.use_only_cookies','1');
session_name('znuny_masks');
session_set_cookie_params([
'lifetime'=>0,
'path'=>'/',
'secure'=>isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off',
'httponly'=>true,
'samesite'=>'Strict'
]);
session_start();
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
function h(string $value):string{
return htmlspecialchars($value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
}
function clean(mixed $value,int $maximum=20000):string{
if(!is_string($value)){
return '';
}
$value=str_replace("\0",'',$value);
return mb_substr(trim($value),0,$maximum);
}
function createId():string{
return bin2hex(random_bytes(12));
}
function defaultData():array{
return [
'settings'=>[
'ticketTypes'=>['Incident','ServiceRequest','Change','Problem'],
'queues'=>['Support','Consulting','Management'],
'services'=>['Basic Support','Managed Service','Internal'],
'states'=>['new','open','pending reminder','closed successful','closed unsuccessful']
],
'masks'=>[
[
'id'=>'beispiel-support',
'name'=>'Supportanruf mit Abschlussnotiz',
'description'=>'Beispiel für ein neues Supportticket mit anschließender Abschlussnotiz.',
'published'=>true,
'updatedAt'=>gmdate('c'),
'steps'=>[
[
'id'=>'beispiel-ticket',
'action'=>'ticket',
'name'=>'Supportticket erstellen',
'type'=>'Incident',
'queue'=>'Support',
'service'=>'Basic Support',
'state'=>'new',
'subject'=>'[{{Kundenkürzel}}][KAT.1] {{Kurzbeschreibung}}',
'body'=>"Kunde rief an: {{Name}}\nTelefonnummer: {{Telefonnummer}}\nGerät: {{Gerät}}\n\nProbleme:\n{{Problembeschreibung}}\n\nFestgestellt:\n{{Festgestellt}}"
],
[
'id'=>'beispiel-notiz',
'action'=>'note',
'name'=>'Abschlussnotiz',
'type'=>'',
'queue'=>'',
'service'=>'',
'state'=>'closed successful',
'subject'=>'Lösung des Problems',
'body'=>"Durchgeführte Maßnahmen:\n{{Maßnahmen}}\n\nLösung:\n{{Lösung}}\n\nInterne Notiz:\n{{Interne Notiz}}"
]
]
]
]
];
}
function initializeStorage():void{
if(!is_file(DATA_FILE)){
$json=json_encode(defaultData(),JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
if(file_put_contents(DATA_FILE,$json,LOCK_EX)===false){
http_response_code(500);
exit('masks.json konnte nicht automatisch angelegt werden. Prüfe die Schreibrechte des Ordners.');
}
@chmod(DATA_FILE,0660);
}
if(!is_file(HTACCESS_FILE)){
$content="<Files \"masks.json\">\nRequire all denied\n</Files>\n";
@file_put_contents(HTACCESS_FILE,$content,LOCK_EX);
}
}
function loadData():array{
initializeStorage();
$handle=fopen(DATA_FILE,'rb');
if($handle===false){
http_response_code(500);
exit('masks.json kann nicht geöffnet werden.');
}
if(!flock($handle,LOCK_SH)){
fclose($handle);
http_response_code(500);
exit('masks.json kann nicht gesperrt werden.');
}
$json=stream_get_contents($handle);
flock($handle,LOCK_UN);
fclose($handle);
try{
$data=json_decode((string)$json,true,512,JSON_THROW_ON_ERROR);
}catch(Throwable){
http_response_code(500);
exit('masks.json enthält ungültiges JSON.');
}
if(!is_array($data)){
http_response_code(500);
exit('masks.json besitzt keine gültige Datenstruktur.');
}
if(!isset($data['settings'])||!is_array($data['settings'])){
$data['settings']=[];
}
if(!isset($data['masks'])||!is_array($data['masks'])){
$data['masks']=[];
}
foreach(['ticketTypes','queues','services','states'] as $name){
if(!isset($data['settings'][$name])||!is_array($data['settings'][$name])){
$data['settings'][$name]=[];
}
}
return $data;
}
function saveData(array $data):void{
try{
$json=json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
}catch(Throwable){
throw new RuntimeException('Die Daten konnten nicht als JSON gespeichert werden.');
}
$temporaryFile=DATA_FILE.'.tmp';
$handle=fopen($temporaryFile,'c+b');
if($handle===false){
throw new RuntimeException('Temporäre JSON-Datei konnte nicht geöffnet werden.');
}
if(!flock($handle,LOCK_EX)){
fclose($handle);
throw new RuntimeException('Temporäre JSON-Datei konnte nicht gesperrt werden.');
}
$success=ftruncate($handle,0);
$success=$success&&rewind($handle);
$success=$success&&fwrite($handle,$json)!==false;
$success=$success&&fflush($handle);
flock($handle,LOCK_UN);
fclose($handle);
if(!$success){
@unlink($temporaryFile);
throw new RuntimeException('masks.json konnte nicht geschrieben werden.');
}
@chmod($temporaryFile,0660);
if(!rename($temporaryFile,DATA_FILE)){
@unlink($temporaryFile);
throw new RuntimeException('masks.json konnte nicht ersetzt werden.');
}
}
function csrfToken():string{
if(!isset($_SESSION['csrf'])||!is_string($_SESSION['csrf'])){
$_SESSION['csrf']=bin2hex(random_bytes(32));
}
return $_SESSION['csrf'];
}
function verifyCsrf():void{
$token=$_POST['csrf']??null;
if(!is_string($token)||!hash_equals(csrfToken(),$token)){
http_response_code(403);
exit('Ungültiger CSRF-Token.');
}
}
function linesToList(mixed $value):array{
if(!is_string($value)){
return [];
}
$lines=preg_split('/\R/u',$value)?:[];
$result=[];
foreach($lines as $line){
$item=clean($line,120);
if($item!==''&&!in_array($item,$result,true)){
$result[]=$item;
}
}
return $result;
}
function findMask(array $data,string $id):?array{
foreach($data['masks'] as $mask){
if(is_array($mask)&&($mask['id']??'')===$id){
return $mask;
}
}
return null;
}
function maskFromPost(?array $existingMask):array{
$name=clean($_POST['name']??'',120);
if($name===''){
throw new RuntimeException('Der Name der Maske fehlt.');
}
$actions=is_array($_POST['step_action']??null)?$_POST['step_action']:[];
$names=is_array($_POST['step_name']??null)?$_POST['step_name']:[];
$types=is_array($_POST['step_type']??null)?$_POST['step_type']:[];
$queues=is_array($_POST['step_queue']??null)?$_POST['step_queue']:[];
$services=is_array($_POST['step_service']??null)?$_POST['step_service']:[];
$states=is_array($_POST['step_state']??null)?$_POST['step_state']:[];
$subjects=is_array($_POST['step_subject']??null)?$_POST['step_subject']:[];
$bodies=is_array($_POST['step_body']??null)?$_POST['step_body']:[];
$stepIds=is_array($_POST['step_id']??null)?$_POST['step_id']:[];
$count=min(count($actions),50);
if($count<1){
throw new RuntimeException('Die Maske benötigt mindestens einen Schritt.');
}
$steps=[];
for($index=0;$index<$count;$index++){
$action=clean($actions[$index]??'',20);
if(!in_array($action,['ticket','note'],true)){
$action='note';
}
$stepName=clean($names[$index]??'',120);
if($stepName===''){
throw new RuntimeException('Jeder Schritt benötigt eine Bezeichnung.');
}
$stepId=clean($stepIds[$index]??'',64);
$steps[]=[
'id'=>$stepId!==''?$stepId:createId(),
'action'=>$action,
'name'=>$stepName,
'type'=>clean($types[$index]??'',120),
'queue'=>clean($queues[$index]??'',120),
'service'=>clean($services[$index]??'',120),
'state'=>clean($states[$index]??'',120),
'subject'=>clean($subjects[$index]??'',500),
'body'=>clean($bodies[$index]??'',20000)
];
}
$maskId=clean($_POST['mask_id']??'',64);
return [
'id'=>$maskId!==''?$maskId:createId(),
'name'=>$name,
'description'=>clean($_POST['description']??'',2000),
'published'=>isset($_POST['published']),
'updatedAt'=>gmdate('c'),
'steps'=>$steps
];
}
function extractPlaceholders(array $mask):array{
$result=[];
foreach($mask['steps']??[] as $step){
if(!is_array($step)){
continue;
}
foreach(['subject','body'] as $field){
preg_match_all('/\{\{([^{}]{1,80})\}\}/u',(string)($step[$field]??''),$matches);
foreach($matches[1]??[] as $value){
$name=trim((string)$value);
if($name!==''&&!in_array($name,$result,true)){
$result[]=$name;
}
}
}
}
return $result;
}
if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'&&(int)($_SERVER['CONTENT_LENGTH']??0)>MAX_REQUEST_SIZE){
http_response_code(413);
exit('Die Anfrage ist zu groß.');
}
$data=loadData();
$page=clean($_GET['_page']??'',30);
$maskId=clean($_GET['_mask']??'',64);
$editId=clean($_GET['_edit']??'',64);
$message='';
$error='';
if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
try{
verifyCsrf();
$action=clean($_POST['action']??'',30);
if($action==='save_settings'){
$data['settings']=[
'ticketTypes'=>linesToList($_POST['ticketTypes']??''),
'queues'=>linesToList($_POST['queues']??''),
'services'=>linesToList($_POST['services']??''),
'states'=>linesToList($_POST['states']??'')
];
saveData($data);
header('Location: ?_page=edit&_saved=settings');
exit;
}
if($action==='save_mask'){
$currentId=clean($_POST['mask_id']??'',64);
$existing=$currentId!==''?findMask($data,$currentId):null;
$mask=maskFromPost($existing);
$replaced=false;
foreach($data['masks'] as $index=>$storedMask){
if(is_array($storedMask)&&($storedMask['id']??'')===$mask['id']){
$data['masks'][$index]=$mask;
$replaced=true;
break;
}
}
if(!$replaced){
$data['masks'][]=$mask;
}
saveData($data);
header('Location: ?_page=edit&_edit='.rawurlencode($mask['id']).'&_saved=mask');
exit;
}
if($action==='delete_mask'){
$id=clean($_POST['mask_id']??'',64);
$data['masks']=array_values(array_filter(
$data['masks'],
static fn(mixed $mask):bool=>!is_array($mask)||($mask['id']??'')!==$id
));
saveData($data);
header('Location: ?_page=edit&_deleted=1');
exit;
}
}catch(Throwable $exception){
$error=$exception->getMessage();
}
}
if(($_GET['_saved']??'')==='settings'){
$message='Feste Werte wurden gespeichert.';
}
if(($_GET['_saved']??'')==='mask'){
$message='Maske wurde gespeichert.';
}
if(isset($_GET['_deleted'])){
$message='Maske wurde gelöscht.';
}
$selectedMask=$maskId!==''?findMask($data,$maskId):null;
if($selectedMask!==null&&!($selectedMask['published']??false)&&$page!=='edit'){
$selectedMask=null;
}
$editedMask=$editId!==''&&$editId!=='new'?findMask($data,$editId):null;
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Znuny Masken</title>
<style>
:root{--bg:#fff;--fg:#141414;--muted:#5a5f66;--border:#d5d7dd;--panel:#f5f6f8;--panel2:#e9ebef;--accent:#0a63ff;--accent-fg:#fff;--danger:#b3261e;--danger-bg:#fde7e7;--success:#1a7f37;--success-bg:#e6f4ea}
@media(prefers-color-scheme:dark){:root{--bg:#0f1113;--fg:#e8e8ea;--muted:#a6adb6;--border:#2b3038;--panel:#17191d;--panel2:#20242a;--accent:#5b9bff;--accent-fg:#0a0d12;--danger:#ff7777;--danger-bg:#3f1d1d;--success:#5bd47e;--success-bg:#163a22}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:Arial,Helvetica,sans-serif;font-size:14px}
header{min-height:58px;padding:8px 18px;border-bottom:1px solid var(--border);background:var(--panel);display:flex;align-items:center;gap:16px}
header strong{font-size:17px}
nav{margin-left:auto;display:flex;gap:8px;align-items:center}
main{max-width:1400px;margin:0 auto;padding:18px}
a{color:var(--accent)}
.button,button{display:inline-block;padding:8px 12px;border:1px solid var(--accent);border-radius:3px;background:var(--accent);color:var(--accent-fg);font:inherit;font-weight:bold;text-decoration:none;cursor:pointer}
.button.secondary,button.secondary{border-color:var(--border);background:var(--panel);color:var(--fg)}
button.danger,.button.danger{border-color:var(--danger);background:var(--danger);color:#fff}
button.small,.button.small{padding:5px 8px;font-size:12px}
input,textarea,select{width:100%;padding:8px;border:1px solid var(--border);border-radius:3px;background:var(--bg);color:var(--fg);font:inherit}
textarea{min-height:100px;resize:vertical}
label{display:block;margin-bottom:5px;color:var(--muted);font-size:12px;font-weight:bold}
h1{margin:0 0 16px;font-size:22px}
h2{margin:0 0 12px;font-size:17px}
h3{margin:0;font-size:15px}
form{margin:0}
.panel{margin-bottom:14px;padding:14px;border:1px solid var(--border);border-radius:4px;background:var(--panel)}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.full{grid-column:1/-1}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.notice,.error{margin-bottom:12px;padding:10px;border-radius:3px}
.notice{border:1px solid var(--success);background:var(--success-bg)}
.error{border:1px solid var(--danger);background:var(--danger-bg)}
.mask-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.mask-card{display:flex;flex-direction:column;gap:10px;padding:14px;border:1px solid var(--border);border-radius:4px;background:var(--panel)}
.mask-card p{margin:0;color:var(--muted);line-height:1.4}
.mask-card .actions{margin-top:auto}
.step{margin-bottom:12px;border:1px solid var(--border);border-radius:4px;background:var(--bg)}
.step-head{display:flex;gap:8px;align-items:center;padding:10px;border-bottom:1px solid var(--border);background:var(--panel2)}
.step-head span{color:var(--muted);font-size:12px}
.step-head button{margin-left:auto}
.step-body{padding:12px}
.placeholder-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.preview-step{margin-bottom:12px;border:1px solid var(--border);border-radius:4px;background:var(--bg)}
.preview-head{display:flex;gap:8px;align-items:center;padding:9px 10px;border-bottom:1px solid var(--border);background:var(--panel2)}
.preview-head button{margin-left:auto}
.preview-body{padding:12px}
.preview-meta{display:grid;grid-template-columns:140px 1fr;gap:5px 10px;margin:0 0 12px}
.preview-meta dt{font-weight:bold;color:var(--muted)}
.preview-meta dd{margin:0}
.preview-text{min-height:60px;padding:10px;border:1px solid var(--border);background:var(--panel);white-space:pre-wrap}
.muted{color:var(--muted);font-size:12px}
.hidden{display:none}
.tabs{display:flex;gap:8px;margin-bottom:14px}
code{padding:2px 4px;background:var(--panel2);border-radius:2px}
@media(max-width:760px){.grid{grid-template-columns:1fr}.full{grid-column:auto}.preview-meta{grid-template-columns:1fr}header{padding:8px 12px}main{padding:12px}}
</style>
</head>
<body>
<header>
<strong>Znuny Masken</strong>
<nav>
./Masken</a>
?_page=editEditor</a>
</nav>
</header>
<main>
<?php if($message!==''): ?>
<div class="notice"><?=h($message)?></div>
<?php endif; ?>
<?php if($error!==''): ?>
<div class="error"><?=h($error)?></div>
<?php endif; ?>
<?php if($page==='edit'): ?>
<h1>Maskenverwaltung</h1>
<div class="tabs">
<button class="secondary" type="button" data-show-tab="masks">Masken</button>
<button class="secondary" type="button" data-show-tab="settings">Feste Werte</button>
</div>
<section data-tab="settings" class="hidden">
<form method="post" class="panel">
<input type="hidden" name="csrf" value="<?=h(csrfToken())?>">
<input type="hidden" name="action" value="save_settings">
<h2>Feste Znuny-Werte</h2>
<div class="grid">
<div>
<label for="ticketTypes">Tickettypen, ein Wert pro Zeile</label>
<textarea id="ticketTypes" name="ticketTypes"><?=h(implode("\n",$data['settings']['ticketTypes']))?></textarea>
</div>
<div>
<label for="queues">Queues, ein Wert pro Zeile</label>
<textarea id="queues" name="queues"><?=h(implode("\n",$data['settings']['queues']))?></textarea>
</div>
<div>
<label for="services">Services, ein Wert pro Zeile</label>
<textarea id="services" name="services"><?=h(implode("\n",$data['settings']['services']))?></textarea>
</div>
<div>
<label for="states">Statuswerte, ein Wert pro Zeile</label>
<textarea id="states" name="states"><?=h(implode("\n",$data['settings']['states']))?></textarea>
</div>
</div>
<div class="actions" style="margin-top:12px">
<button type="submit">Feste Werte speichern</button>
</div>
</form>
</section>
<section data-tab="masks">
<?php if($editId===''): ?>
<div class="actions" style="margin-bottom:14px">
?_page=edit&amp;_edit=newNeue Maske</a>
</div>
<div class="mask-list">
<?php foreach($data['masks'] as $mask): ?>
<?php if(!is_array($mask)){continue;} ?>
<div class="mask-card">
<h3><?=h((string)($mask['name']??''))?></h3>
<p><?=nl2br(h((string)($mask['description']??'')))?></p>
<div class="muted">
<?=count(is_array($mask['steps']??null)?$mask['steps']:[])?> Schritte ·
<?=($mask['published']??false)?'Veröffentlicht':'Verborgen'?>
</div>
<div class="actions">
($mask['id']??''))?>">Bearbeiten</a>
($mask['id']??''))?>" target="_blank" rel="noopener">Testen</a>
<form method="post" onsubmit="return confirm('Maske wirklich löschen?')">
<input type="hidden" name="csrf" value="<?=h(csrfToken())?>">
<input type="hidden" name="action" value="delete_mask">
<input type="hidden" name="mask_id" value="<?=h((string)($mask['id']??''))?>">
<button class="danger small" type="submit">Löschen</button>
</form>
</div>
</div>
<?php endforeach; ?>
<?php if($data['masks']===[]): ?>
<div class="panel">Noch keine Masken vorhanden.</div>
<?php endif; ?>
</div>
<?php else: ?>
<?php
$formMask=$editedMask??[
'id'=>'',
'name'=>'',
'description'=>'',
'published'=>true,
'steps'=>[
[
'id'=>'',
'action'=>'ticket',
'name'=>'Ticket erstellen',
'type'=>'',
'queue'=>'',
'service'=>'',
'state'=>'new',
'subject'=>'',
'body'=>''
]
]
];
?>
<form method="post" id="maskForm">
<input type="hidden" name="csrf" value="<?=h(csrfToken())?>">
<input type="hidden" name="action" value="save_mask">
<input type="hidden" name="mask_id" value="<?=h((string)($formMask['id']??''))?>">
<div class="panel">
<h2>Maskeneigenschaften</h2>
<div class="grid">
<div>
<label for="name">Name</label>
<input id="name" name="name" maxlength="120" required value="<?=h((string)($formMask['name']??''))?>">
</div>
<div>
<label>Veröffentlichung</label>
<label style="font-size:14px;color:var(--fg);font-weight:normal">
<input style="width:auto" type="checkbox" name="published" <?=($formMask['published']??false)?'checked':''?>>
Auf der Startseite anzeigen
</label>
</div>
<div class="full">
<label for="description">Beschreibung</label>
<textarea id="description" name="description" maxlength="2000"><?=h((string)($formMask['description']??''))?></textarea>
</div>
</div>
</div>
<div class="panel">
<div class="actions" style="justify-content:space-between;margin-bottom:12px">
<h2>Ticketverlauf</h2>
<button type="button" id="addStep">Schritt hinzufügen</button>
</div>
<div class="muted" style="margin-bottom:12px">
Platzhalter werden beispielsweise als <code>{{Name}}</code> oder <code>{{Gerät}}</code> geschrieben.
</div>
<div id="steps">
<?php foreach($formMask['steps'] as $step): ?>
<div class="step">
<div class="step-head">
<strong data-step-title><?=h((string)($step['name']??'Schritt'))?></strong>
<span data-step-kind><?=($step['action']??'note')==='ticket'?'Neues Ticket':'Notiz'?></span>
<button class="danger small" type="button" data-remove-step>Entfernen</button>
</div>
<div class="step-body">
<input type="hidden" name="step_id[]" value="<?=h((string)($step['id']??''))?>">
<div class="grid">
<div>
<label>Schrittbezeichnung</label>
<input name="step_name[]" required maxlength="120" value="<?=h((string)($step['name']??''))?>" data-step-name>
</div>
<div>
<label>Aktion</label>
<select name="step_action[]" data-step-action>
<option value="ticket" <?=($step['action']??'')==='ticket'?'selected':''?>>Neues Ticket</option>
<option value="note" <?=($step['action']??'')==='note'?'selected':''?>>Notiz</option>
</select>
</div>
<div>
<label>Tickettyp</label>
<input name="step_type[]" list="ticketTypeList" maxlength="120" value="<?=h((string)($step['type']??''))?>">
</div>
<div>
<label>Queue</label>
<input name="step_queue[]" list="queueList" maxlength="120" value="<?=h((string)($step['queue']??''))?>">
</div>
<div>
<label>Service</label>
<input name="step_service[]" list="serviceList" maxlength="120" value="<?=h((string)($step['service']??''))?>">
</div>
<div>
<label>Status</label>
<input name="step_state[]" list="stateList" maxlength="120" value="<?=h((string)($step['state']??''))?>">
</div>
<div class="full">
<label>Betreff</label>
<input name="step_subject[]" maxlength="500" value="<?=h((string)($step['subject']??''))?>">
</div>
<div class="full">
<label>Textvorlage</label>
<textarea name="step_body[]" maxlength="20000"><?=h((string)($step['body']??''))?></textarea>
</div>
</div>
</div>
</div>
<?php endforeach; ?>
</div>
<div class="actions">
<button type="submit">Maske speichern</button>
?_page=editAbbrechen</a>
</div>
</div>
</form>
<datalist id="ticketTypeList">
<?php foreach($data['settings']['ticketTypes'] as $value): ?>
<option value="<?=h((string)$value)?>">
<?php endforeach; ?>
</datalist>
<datalist id="queueList">
<?php foreach($data['settings']['queues'] as $value): ?>
<option value="<?=h((string)$value)?>">
<?php endforeach; ?>
</datalist>
<datalist id="serviceList">
<?php foreach($data['settings']['services'] as $value): ?>
<option value="<?=h((string)$value)?>">
<?php endforeach; ?>
</datalist>
<datalist id="stateList">
<?php foreach($data['settings']['states'] as $value): ?>
<option value="<?=h((string)$value)?>">
<?php endforeach; ?>
</datalist>
<template id="stepTemplate">
<div class="step">
<div class="step-head">
<strong data-step-title>Neuer Schritt</strong>
<span data-step-kind>Notiz</span>
<button class="danger small" type="button" data-remove-step>Entfernen</button>
</div>
<div class="step-body">
<input type="hidden" name="step_id[]" value="">
<div class="grid">
<div>
<label>Schrittbezeichnung</label>
<input name="step_name[]" required maxlength="120" value="Neuer Schritt" data-step-name>
</div>
<div>
<label>Aktion</label>
<select name="step_action[]" data-step-action>
<option value="ticket">Neues Ticket</option>
<option value="note" selected>Notiz</option>
</select>
</div>
<div>
<label>Tickettyp</label>
<input name="step_type[]" list="ticketTypeList" maxlength="120">
</div>
<div>
<label>Queue</label>
<input name="step_queue[]" list="queueList" maxlength="120">
</div>
<div>
<label>Service</label>
<input name="step_service[]" list="serviceList" maxlength="120">
</div>
<div>
<label>Status</label>
<input name="step_state[]" list="stateList" maxlength="120">
</div>
<div class="full">
<label>Betreff</label>
<input name="step_subject[]" maxlength="500">
</div>
<div class="full">
<label>Textvorlage</label>
<textarea name="step_body[]" maxlength="20000"></textarea>
</div>
</div>
</div>
</div>
</template>
<?php endif; ?>
</section>
<?php elseif($selectedMask!==null): ?>
<?php $placeholderNames=extractPlaceholders($selectedMask); ?>
<h1><?=h((string)($selectedMask['name']??''))?></h1>
<?php if(($selectedMask['description']??'')!==''): ?>
<div class="panel"><?=nl2br(h((string)$selectedMask['description']))?></div>
<?php endif; ?>
<div class="panel">
<h2>Platzhalter ausfüllen</h2>
<?php if($placeholderNames===[]): ?>
<div class="muted">Diese Maske enthält keine Platzhalter.</div>
<?php else: ?>
<div class="placeholder-grid">
<?php foreach($placeholderNames as $placeholder): ?>
<div>
<label for="field_<?=h(hash('sha256',$placeholder))?>"><?=h($placeholder)?></label>
<textarea id="field_<?=h(hash('sha256',$placeholder))?>" data-placeholder="<?=h($placeholder)?>" rows="2"></textarea>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>
</div>
<div class="actions" style="margin-bottom:14px">
<button type="button" id="copyWorkflow">Gesamten Verlauf kopieren</button>
<button class="secondary" type="button" id="clearFields">Eingaben leeren</button>
</div>
<div id="workflowPreview"></div>
<script id="maskData" type="application/json"><?=json_encode($selectedMask,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
<?php else: ?>
<h1>Verfügbare Znuny-Masken</h1>
<div class="mask-list">
<?php
$publishedCount=0;
foreach($data['masks'] as $mask):
if(!is_array($mask)||!($mask['published']??false)){
continue;
}
$publishedCount++;
?>
<div class="mask-card">
<h3><?=h((string)($mask['name']??''))?></h3>
<p><?=nl2br(h((string)($mask['description']??'')))?></p>
<div class="muted"><?=count(is_array($mask['steps']??null)?$mask['steps']:[])?> Schritte</div>
<div class="actions">
($mask['id']??''))?>">Maske verwenden</a>
</div>
</div>
<?php endforeach; ?>
<?php if($publishedCount===0): ?>
<div class="panel">Es sind keine veröffentlichten Masken vorhanden.</div>
<?php endif; ?>
</div>
<?php endif; ?>
</main>
<script>
(function(){
"use strict";
document.querySelectorAll("[data-show-tab]").forEach(function(button){
button.addEventListener("click",function(){
document.querySelectorAll("[data-tab]").forEach(function(section){
section.classList.toggle("hidden",section.dataset.tab!==button.dataset.showTab);
});
});
});
var steps=document.getElementById("steps");
var template=document.getElementById("stepTemplate");
var addStep=document.getElementById("addStep");
function bindStep(step){
var remove=step.querySelector("[data-remove-step]");
var name=step.querySelector("[data-step-name]");
var action=step.querySelector("[data-step-action]");
var title=step.querySelector("[data-step-title]");
var kind=step.querySelector("[data-step-kind]");
if(remove){
remove.addEventListener("click",function(){
if(document.querySelectorAll("#steps .step").length<=1){
alert("Mindestens ein Schritt ist erforderlich.");
return;
}
step.remove();
});
}
if(name&&title){
name.addEventListener("input",function(){
title.textContent=name.value||"Unbenannter Schritt";
});
}
if(action&&kind){
action.addEventListener("change",function(){
kind.textContent=action.value==="ticket"?"Neues Ticket":"Notiz";
});
}
}
document.querySelectorAll("#steps .step").forEach(bindStep);
if(addStep&&steps&&template){
addStep.addEventListener("click",function(){
var step=template.content.firstElementChild.cloneNode(true);
steps.appendChild(step);
bindStep(step);
step.scrollIntoView({behavior:"smooth",block:"center"});
});
}
var maskData=document.getElementById("maskData");
if(!maskData){
return;
}
var mask=JSON.parse(maskData.textContent);
var preview=document.getElementById("workflowPreview");
var fields=Array.from(document.querySelectorAll("[data-placeholder]"));
function values(){
var result={};
fields.forEach(function(field){
result[field.dataset.placeholder]=field.value;
});
return result;
}
function replacePlaceholders(value,replacements){
return String(value||"").replace(/\{\{([^{}]{1,80})\}\}/gu,function(match,key){
return replacements[key.trim()]||"";
});
}
function stepText(step,index,replacements){
var lines=[];
lines.push((index+1)+". "+String(step.name||"Schritt"));
lines.push("Aktion: "+(step.action==="ticket"?"Neues Ticket":"Notiz"));
if(step.type){
lines.push("Tickettyp: "+step.type);
}
if(step.queue){
lines.push("Queue: "+step.queue);
}
if(step.service){
lines.push("Service: "+step.service);
}
if(step.state){
lines.push("Status: "+step.state);
}
if(step.subject){
lines.push("Betreff: "+replacePlaceholders(step.subject,replacements));
}
lines.push("");
lines.push(replacePlaceholders(step.body,replacements));
return lines.join("\n").trim();
}
function fallbackCopy(value){
var textarea=document.createElement("textarea");
textarea.value=value;
textarea.style.position="fixed";
textarea.style.left="-9999px";
document.body.appendChild(textarea);
textarea.focus();
textarea.select();
document.execCommand("copy");
textarea.remove();
}
function copyText(value,button){
function copied(){
var original=button.textContent;
button.textContent="Kopiert";
setTimeout(function(){
button.textContent=original;
},1200);
}
if(navigator.clipboard&&window.isSecureContext){
navigator.clipboard.writeText(value).then(copied).catch(function(){
fallbackCopy(value);
copied();
});
return;
}
fallbackCopy(value);
copied();
}
function addMeta(list,label,value){
if(!value){
return;
}
var term=document.createElement("dt");
var description=document.createElement("dd");
term.textContent=label;
description.textContent=value;
list.append(term,description);
}
function render(){
var replacements=values();
preview.textContent="";
(mask.steps||[]).forEach(function(step,index){
var section=document.createElement("section");
section.className="preview-step";
var header=document.createElement("div");
header.className="preview-head";
var title=document.createElement("strong");
title.textContent=(index+1)+". "+String(step.name||"Schritt");
var kind=document.createElement("span");
kind.className="muted";
kind.textContent=step.action==="ticket"?"Neues Ticket":"Notiz";
var copyButton=document.createElement("button");
copyButton.type="button";
copyButton.className="secondary small";
copyButton.textContent="Schritt kopieren";
copyButton.addEventListener("click",function(){
copyText(stepText(step,index,values()),copyButton);
});
header.append(title,kind,copyButton);
var body=document.createElement("div");
body.className="preview-body";
var meta=document.createElement("dl");
meta.className="preview-meta";
addMeta(meta,"Aktion",step.action==="ticket"?"Neues Ticket":"Notiz");
addMeta(meta,"Tickettyp",step.type);
addMeta(meta,"Queue",step.queue);
addMeta(meta,"Service",step.service);
addMeta(meta,"Status",step.state);
addMeta(meta,"Betreff",replacePlaceholders(step.subject,replacements));
var content=document.createElement("div");
content.className="preview-text";
content.textContent=replacePlaceholders(step.body,replacements);
body.append(meta,content);
section.append(header,body);
preview.appendChild(section);
});
}
fields.forEach(function(field){
field.addEventListener("input",render);
});
var copyWorkflow=document.getElementById("copyWorkflow");
if(copyWorkflow){
copyWorkflow.addEventListener("click",function(){
var replacements=values();
var output=(mask.steps||[]).map(function(step,index){
return stepText(step,index,replacements);
}).join("\n\n========================================\n\n");
copyText(output,copyWorkflow);
});
}
var clearFields=document.getElementById("clearFields");
if(clearFields){
clearFields.addEventListener("click",function(){
fields.forEach(function(field){
field.value="";
});
render();
});
}
render();
})();
</script>
</body>
</html>
