<?php
declare(strict_types=1);
ini_set('display_errors','0');
ini_set('session.use_strict_mode','1');
ini_set('session.use_only_cookies','1');
session_name('znuny_mask_session');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>!empty($_SERVER['HTTPS']),'httponly'=>true,'samesite'=>'Strict']);
session_start();
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
const DATA_DIR=__DIR__.'/data';
const DATA_FILE=DATA_DIR.'/masks.json';
const MAX_POST_SIZE=1048576;
function e(string $value):string{return htmlspecialchars($value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function id():string{return bin2hex(random_bytes(8));}
function initializeStorage():void{
if(!is_dir(DATA_DIR)&&!mkdir(DATA_DIR,0700,true)&&!is_dir(DATA_DIR)){http_response_code(500);exit('Datenspeicher konnte nicht erstellt werden.');}
if(!file_exists(DATA_DIR.'/.htaccess')){file_put_contents(DATA_DIR.'/.htaccess',"Require all denied\nDeny from all\n",LOCK_EX);@chmod(DATA_DIR.'/.htaccess',0600);}
if(!file_exists(DATA_FILE)){
$initial=['settings'=>['ticketTypes'=>['Incident','ServiceRequest','Change','Problem'],'queues'=>['Support'],'services'=>['Basic Support','Managed Service','Internal'],'states'=>['new','open','pending reminder','closed successful','closed unsuccessful']],'masks'=>[]];
file_put_contents(DATA_FILE,json_encode($initial,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),LOCK_EX);
@chmod(DATA_FILE,0600);
}
}
function loadData():array{
initializeStorage();
$handle=fopen(DATA_FILE,'rb');
if(!$handle){http_response_code(500);exit('Datenspeicher nicht lesbar.');}
flock($handle,LOCK_SH);
$json=stream_get_contents($handle);
flock($handle,LOCK_UN);
fclose($handle);
$data=json_decode($json?:'',true);
if(!is_array($data)||!isset($data['settings'],$data['masks'])||!is_array($data['settings'])||!is_array($data['masks'])){http_response_code(500);exit('Datenspeicher ist beschädigt.');}
return $data;
}
function saveData(array $data):void{
$json=json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
$temp=DATA_FILE.'.tmp.'.bin2hex(random_bytes(4));
$handle=fopen($temp,'xb');
if(!$handle){http_response_code(500);exit('Temporäre Datei konnte nicht erstellt werden.');}
flock($handle,LOCK_EX);
fwrite($handle,$json);
fflush($handle);
flock($handle,LOCK_UN);
fclose($handle);
@chmod($temp,0600);
if(!rename($temp,DATA_FILE)){@unlink($temp);http_response_code(500);exit('Datenspeicher konnte nicht aktualisiert werden.');}
}
function csrf():string{
if(empty($_SESSION['csrf'])){$_SESSION['csrf']=bin2hex(random_bytes(32));}
return $_SESSION['csrf'];
}
function verifyCsrf():void{
if(!isset($_POST['csrf'])||!is_string($_POST['csrf'])||!hash_equals(csrf(),$_POST['csrf'])){http_response_code(403);exit('Ungültige Anfrage.');}
}
function cleanText(mixed $value,int $max=10000):string{
$value=is_string($value)?trim($value):'';
return mb_substr($value,0,$max);
}
function cleanList(mixed $value):array{
if(!is_string($value)){return [];}
$items=preg_split('/\R/u',$value)?:[];
$items=array_map(static fn($item)=>mb_substr(trim((string)$item),0,120),$items);
return array_values(array_unique(array_filter($items,static fn($item)=>$item!=='')));
}
function findMask(array $data,string $maskId):?array{
foreach($data['masks'] as $mask){if(($mask['id']??'')===$maskId){return $mask;}}
return null;
}
function placeholders(array $mask):array{
$found=[];
foreach($mask['steps']??[] as $step){
foreach(['subject','body'] as $field){
preg_match_all('/\{\{([A-Za-zÄÖÜäöüß0-9 _.-]{1,80})\}\}/u',(string)($step[$field]??''),$matches);
foreach($matches[1]??[] as $name){$name=trim($name);if($name!==''&&!in_array($name,$found,true)){$found[]=$name;}}
}
}
return $found;
}
function replacePlaceholders(string $text,array $values):string{
return preg_replace_callback('/\{\{([A-Za-zÄÖÜäöüß0-9 _.-]{1,80})\}\}/u',static function(array $match)use($values):string{
$key=trim($match[1]);
return cleanText($values[$key]??'',5000);
},$text)??$text;
}
function createMaskFromPost():array{
$name=cleanText($_POST['name']??'',120);
$description=cleanText($_POST['description']??'',1000);
$published=isset($_POST['published']);
$stepActions=$_POST['step_action']??[];
$stepNames=$_POST['step_name']??[];
$stepTypes=$_POST['step_type']??[];
$stepQueues=$_POST['step_queue']??[];
$stepServices=$_POST['step_service']??[];
$stepStates=$_POST['step_state']??[];
$stepSubjects=$_POST['step_subject']??[];
$stepBodies=$_POST['step_body']??[];
$steps=[];
$count=min(max(count(is_array($stepActions)?$stepActions:[]),0),50);
for($i=0;$i<$count;$i++){
$action=cleanText($stepActions[$i]??'',20);
if(!in_array($action,['ticket','note'],true)){$action='note';}
$steps[]=['id'=>id(),'action'=>$action,'name'=>cleanText($stepNames[$i]??'',120),'type'=>cleanText($stepTypes[$i]??'',120),'queue'=>cleanText($stepQueues[$i]??'',120),'service'=>cleanText($stepServices[$i]??'',120),'state'=>cleanText($stepStates[$i]??'',120),'subject'=>cleanText($stepSubjects[$i]??'',500),'body'=>cleanText($stepBodies[$i]??'',20000)];
}
if($name===''||$steps===[]){throw new RuntimeException('Name und mindestens ein Schritt sind erforderlich.');}
return ['id'=>cleanText($_POST['mask_id']??'',32)?:id(),'name'=>$name,'description'=>$description,'published'=>$published,'updatedAt'=>gmdate('c'),'steps'=>$steps];
}
function adminPassword():string{return (string)(getenv('APP_ADMIN_PASSWORD')?:'');}
function isAdmin():bool{return !empty($_SESSION['admin']);}
function requireAdmin():void{if(!isAdmin()){header('Location: ?_page=login');exit;}}
if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'&&(int)($_SERVER['CONTENT_LENGTH']??0)>MAX_POST_SIZE){http_response_code(413);exit('Anfrage ist zu groß.');}
$data=loadData();
$page=cleanText($_GET['_page']??'',20);
$message='';
$error='';
if($_SERVER['REQUEST_METHOD']==='POST'){
try{
verifyCsrf();
$action=cleanText($_POST['action']??'',30);
if($action==='login'){
$password=cleanText($_POST['password']??'',500);
if(adminPassword()===''){throw new RuntimeException('APP_ADMIN_PASSWORD ist auf dem Server nicht gesetzt.');}
if(!hash_equals(adminPassword(),$password)){throw new RuntimeException('Anmeldung fehlgeschlagen.');}
session_regenerate_id(true);
$_SESSION['admin']=true;
header('Location: ?_page=edit');
exit;
}
if($action==='logout'){
$_SESSION=[];
session_regenerate_id(true);
header('Location: ./');
exit;
}
requireAdmin();
if($action==='save_settings'){
$data['settings']['ticketTypes']=cleanList($_POST['ticketTypes']??'');
$data['settings']['queues']=cleanList($_POST['queues']??'');
$data['settings']['services']=cleanList($_POST['services']??'');
$data['settings']['states']=cleanList($_POST['states']??'');
saveData($data);
$message='Einstellungen gespeichert.';
}
if($action==='save_mask'){
$mask=createMaskFromPost();
$replaced=false;
foreach($data['masks'] as $index=>$existing){
if(($existing['id']??'')===$mask['id']){$data['masks'][$index]=$mask;$replaced=true;break;}
}
if(!$replaced){$data['masks'][]=$mask;}
saveData($data);
header('Location: ?_page=edit&_edit='.rawurlencode($mask['id']).'&_saved=1');
exit;
}
if($action==='delete_mask'){
$maskId=cleanText($_POST['mask_id']??'',32);
$data['masks']=array_values(array_filter($data['masks'],static fn($mask)=>($mask['id']??'')!==$maskId));
saveData($data);
header('Location: ?_page=edit');
exit;
}
}catch(Throwable $exception){$error=$exception->getMessage();}
}
if(isset($_GET['_saved'])){$message='Maske gespeichert.';}
$editId=cleanText($_GET['_edit']??'',32);
$editMask=$editId!==''?findMask($data,$editId):null;
$useId=cleanText($_GET['_mask']??'',32);
$useMask=$useId!==''?findMask($data,$useId):null;
if($useMask&&!($useMask['published']??false)&&!isAdmin()){$useMask=null;}
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Znuny Masken</title>
<style>
:root{--bg:#fff;--fg:#141414;--muted:#5a5f66;--border:#d5d7dd;--panel:#f5f6f8;--panel2:#e9ebef;--accent:#0a63ff;--accentfg:#fff;--danger:#b3261e;--dangerbg:#fde7e7;--success:#1a7f37;--successbg:#e6f4ea;--shadow:rgba(0,0,0,.18)}
@media(prefers-color-scheme:dark){:root{--bg:#0f1113;--fg:#e8e8ea;--muted:#a6adb6;--border:#2b3038;--panel:#17191d;--panel2:#20242a;--accent:#5b9bff;--accentfg:#0a0d12;--danger:#ff8080;--dangerbg:#3f1d1d;--success:#5bd47e;--successbg:#163a22;--shadow:rgba(0,0,0,.6)}}
*{box-sizing:border-box}
body{font-family:Arial,Helvetica,sans-serif;margin:0;background:var(--bg);color:var(--fg)}
header{height:58px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;padding:0 18px;background:var(--panel)}
header strong{font-size:17px}
header nav{margin-left:auto;display:flex;gap:8px;align-items:center}
main{max-width:1400px;margin:0 auto;padding:18px}
a{color:var(--accent)}
button,.button{display:inline-block;border:1px solid var(--accent);border-radius:4px;padding:8px 12px;background:var(--accent);color:var(--accentfg);font-size:14px;font-weight:bold;text-decoration:none;cursor:pointer}
button.secondary,.button.secondary{background:var(--panel);border-color:var(--border);color:var(--fg)}
button.danger{background:var(--danger);border-color:var(--danger);color:#fff}
button.small,.button.small{padding:5px 8px;font-size:12px}
input,textarea,select{width:100%;padding:8px;border:1px solid var(--border);border-radius:3px;background:var(--bg);color:var(--fg);font:inherit}
textarea{min-height:90px;resize:vertical}
label{display:block;font-size:12px;font-weight:bold;color:var(--muted);margin-bottom:5px}
h1{font-size:22px;margin:0 0 16px}
h2{font-size:17px;margin:0 0 12px}
h3{font-size:15px;margin:0}
.panel{border:1px solid var(--border);background:var(--panel);border-radius:4px;padding:14px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.grid .full{grid-column:1/-1}
.mask-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.mask-card{border:1px solid var(--border);background:var(--panel);border-radius:4px;padding:14px;display:flex;flex-direction:column;gap:10px}
.mask-card p{margin:0;color:var(--muted);line-height:1.4}
.mask-card .button{align-self:flex-start;margin-top:auto}
.notice{border:1px solid var(--success);background:var(--successbg);padding:10px;margin-bottom:12px;border-radius:4px}
.error{border:1px solid var(--danger);background:var(--dangerbg);padding:10px;margin-bottom:12px;border-radius:4px}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.step{border:1px solid var(--border);background:var(--bg);border-radius:4px;margin-bottom:12px}
.step-head{display:flex;gap:8px;align-items:center;padding:10px;background:var(--panel2);border-bottom:1px solid var(--border);cursor:pointer}
.step-head span{font-size:12px;color:var(--muted)}
.step-head button{margin-left:auto}
.step-body{padding:12px}
.placeholder-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.preview-step{border:1px solid var(--border);background:var(--bg);border-radius:4px;margin-bottom:12px}
.preview-head{display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--panel2);border-bottom:1px solid var(--border)}
.preview-head button{margin-left:auto}
.preview-content{padding:12px}
.preview-content dl{display:grid;grid-template-columns:140px 1fr;gap:5px 10px;margin:0 0 12px}
.preview-content dt{font-weight:bold;color:var(--muted)}
.preview-content dd{margin:0}
.preview-text{white-space:pre-wrap;border:1px solid var(--border);padding:10px;background:var(--panel);min-height:60px}
.tabs{display:flex;gap:8px;margin-bottom:14px}
.hidden{display:none!important}
.muted{color:var(--muted);font-size:12px}
@media(max-width:760px){.grid{grid-template-columns:1fr}.grid .full{grid-column:auto}header{padding-left:12px}main{padding:12px}.preview-content dl{grid-template-columns:1fr}.preview-content dt{margin-top:5px}}
</style>
</head>
<body>
<header>
<strong>Znuny Masken</strong>
<nav>
./Masken</a>
<?php if(isAdmin()): ?>
?_page=editEditor</a>
<form method="post">
<input type="hidden" name="csrf" value="<?=e(csrf())?>">
<input type="hidden" name="action" value="logout">
<button class="secondary small" type="submit">Abmelden</button>
</form>
<?php else: ?>
?_page=loginEditor</a>
<?php endif; ?>
</nav>
</header>
<main>
<?php if($message!==''): ?><div class="notice"><?=e($message)?></div><?php endif; ?>
<?php if($error!==''): ?><div class="error"><?=e($error)?></div><?php endif; ?>
<?php if($page==='login'): ?>
<h1>Administration</h1>
<div class="panel" style="max-width:450px">
<?php if(adminPassword()===''): ?><div class="error">Auf dem Server muss zuerst die Umgebungsvariable <code>APP_ADMIN_PASSWORD</code> gesetzt werden.</div><?php endif; ?>
<form method="post">
<input type="hidden" name="csrf" value="<?=e(csrf())?>">
<input type="hidden" name="action" value="login">
<label for="password">Administrationspasswort</label>
<input id="password" name="password" type="password" required autocomplete="current-password">
<div class="actions" style="margin-top:12px"><button type="submit">Anmelden</button></div>
</form>
</div>
<?php elseif($page==='edit'): requireAdmin(); ?>
<h1>Maskenverwaltung</h1>
<div class="tabs">
<button type="button" class="secondary" data-tab-button="masks">Masken</button>
<button type="button" class="secondary" data-tab-button="settings">Feste Werte</button>
</div>
<section data-tab="settings" class="hidden">
<form method="post" class="panel">
<input type="hidden" name="csrf" value="<?=e(csrf())?>">
<input type="hidden" name="action" value="save_settings">
<h2>Feste Znuny-Werte</h2>
<div class="grid">
<div><label for="ticketTypes">Tickettypen, ein Wert pro Zeile</label><textarea id="ticketTypes" name="ticketTypes"><?=e(implode("\n",$data['settings']['ticketTypes']??[]))?></textarea></div>
<div><label for="queues">Queues, ein Wert pro Zeile</label><textarea id="queues" name="queues"><?=e(implode("\n",$data['settings']['queues']??[]))?></textarea></div>
<div><label for="services">Services, ein Wert pro Zeile</label><textarea id="services" name="services"><?=e(implode("\n",$data['settings']['services']??[]))?></textarea></div>
<div><label for="states">Statuswerte, ein Wert pro Zeile</label><textarea id="states" name="states"><?=e(implode("\n",$data['settings']['states']??[]))?></textarea></div>
</div>
<div class="actions" style="margin-top:12px"><button type="submit">Einstellungen speichern</button></div>
</form>
</section>
<section data-tab="masks">
<div class="actions" style="margin-bottom:14px">
?_page=edit&_edit=newNeue Maske</a>
</div>
<?php if($editId===''): ?>
<div class="mask-list">
<?php foreach($data['masks'] as $mask): ?>
<div class="mask-card">
<h3><?=e((string)($mask['name']??''))?></h3>
<p><?=e((string)($mask['description']??''))?></p>
<div class="muted"><?=count($mask['steps']??[])?> Schritte · <?=($mask['published']??false)?'Veröffentlicht':'Verborgen'?></div>
<div class="actions">
mask['id'])?>">Bearbeiten</a>
mask['id'])?>" target="_blank">Testen</a>
<form method="post" onsubmit="return confirm('Maske wirklich löschen?')">
<input type="hidden" name="csrf" value="<?=e(csrf())?>">
<input type="hidden" name="action" value="delete_mask">
<input type="hidden" name="mask_id" value="<?=e((string)$mask['id'])?>">
<button class="danger small" type="submit">Löschen</button>
</form>
</div>
</div>
<?php endforeach; ?>
<?php if($data['masks']===[]): ?><div class="panel">Noch keine Masken vorhanden.</div><?php endif; ?>
</div>
<?php else:
$formMask=$editMask??['id'=>'','name'=>'','description'=>'','published'=>true,'steps'=>[['action'=>'ticket','name'=>'Ticket erstellen','type'=>'','queue'=>'','service'=>'','state'=>'new','subject'=>'','body'=>'']]];
?>
<form method="post" id="maskForm">
<input type="hidden" name="csrf" value="<?=e(csrf())?>">
<input type="hidden" name="action" value="save_mask">
<input type="hidden" name="mask_id" value="<?=e((string)($formMask['id']??''))?>">
<div class="panel">
<h2>Maskeneigenschaften</h2>
<div class="grid">
<div><label for="name">Name</label><input id="name" name="name" maxlength="120" required value="<?=e((string)($formMask['name']??''))?>"></div>
<div><label><input style="width:auto" type="checkbox" name="published" <?=($formMask['published']??false)?'checked':''?>> Auf der Startseite veröffentlichen</label></div>
<div class="full"><label for="description">Beschreibung</label><textarea id="description" name="description" maxlength="1000"><?=e((string)($formMask['description']??''))?></textarea></div>
</div>
</div>
<div class="panel">
<div class="actions" style="justify-content:space-between;margin-bottom:12px">
<h2>Ticketverlauf</h2>
<button type="button" id="addStep">Schritt hinzufügen</button>
</div>
<div id="steps">
<?php foreach($formMask['steps']??[] as $step): ?>
<div class="step">
<div class="step-head"><strong data-step-title><?=e((string)($step['name']??'Schritt'))?></strong><span data-step-kind><?=($step['action']??'note')==='ticket'?'Neues Ticket':'Notiz'?></span><button type="button" class="danger small" data-remove-step>Entfernen</button></div>
<div class="step-body">
<div class="grid">
<div><label>Schrittbezeichnung</label><input name="step_name[]" required maxlength="120" value="<?=e((string)($step['name']??''))?>" data-step-name></div>
<div><label>Znuny-Aktion</label><select name="step_action[]" data-step-action><option value="ticket" <?=($step['action']??'')==='ticket'?'selected':''?>>Neues Ticket</option><option value="note" <?=($step['action']??'')==='note'?'selected':''?>>Notiz</option></select></div>
<div><label>Tickettyp</label><input name="step_type[]" list="ticketTypeList" value="<?=e((string)($step['type']??''))?>"></div>
<div><label>Queue</label><input name="step_queue[]" list="queueList" value="<?=e((string)($step['queue']??''))?>"></div>
<div><label>Service</label><input name="step_service[]" list="serviceList" value="<?=e((string)($step['service']??''))?>"></div>
<div><label>Status</label><input name="step_state[]" list="stateList" value="<?=e((string)($step['state']??''))?>"></div>
<div class="full"><label>Betreff, Platzhalter beispielsweise {{Name}}</label><input name="step_subject[]" maxlength="500" value="<?=e((string)($step['subject']??''))?>"></div>
<div class="full"><label>Textvorlage</label><textarea name="step_body[]" maxlength="20000"><?=e((string)($step['body']??''))?></textarea></div>
</div>
</div>
</div>
<?php endforeach; ?>
</div>
<div class="actions"><button type="submit">Maske speichern</button>?_page=editAbbrechen</a></div>
</div>
</form>
<datalist id="ticketTypeList"><?php foreach($data['settings']['ticketTypes']??[] as $value): ?><option value="<?=e((string)$value)?>"><?php endforeach; ?></datalist>
<datalist id="queueList"><?php foreach($data['settings']['queues']??[] as $value): ?><option value="<?=e((string)$value)?>"><?php endforeach; ?></datalist>
<datalist id="serviceList"><?php foreach($data['settings']['services']??[] as $value): ?><option value="<?=e((string)$value)?>"><?php endforeach; ?></datalist>
<datalist id="stateList"><?php foreach($data['settings']['states']??[] as $value): ?><option value="<?=e((string)$value)?>"><?php endforeach; ?></datalist>
<template id="stepTemplate">
<div class="step">
<div class="step-head"><strong data-step-title>Neuer Schritt</strong><span data-step-kind>Notiz</span><button type="button" class="danger small" data-remove-step>Entfernen</button></div>
<div class="step-body">
<div class="grid">
<div><label>Schrittbezeichnung</label><input name="step_name[]" required maxlength="120" value="Neuer Schritt" data-step-name></div>
<div><label>Znuny-Aktion</label><select name="step_action[]" data-step-action><option value="ticket">Neues Ticket</option><option value="note" selected>Notiz</option></select></div>
<div><label>Tickettyp</label><input name="step_type[]" list="ticketTypeList"></div>
<div><label>Queue</label><input name="step_queue[]" list="queueList"></div>
<div><label>Service</label><input name="step_service[]" list="serviceList"></div>
<div><label>Status</label><input name="step_state[]" list="stateList"></div>
<div class="full"><label>Betreff, Platzhalter beispielsweise {{Name}}</label><input name="step_subject[]" maxlength="500"></div>
<div class="full"><label>Textvorlage</label><textarea name="step_body[]" maxlength="20000"></textarea></div>
</div>
</div>
</div>
</template>
<?php endif; ?>
</section>
<?php elseif($useMask): $maskPlaceholders=placeholders($useMask); ?>
<h1><?=e((string)$useMask['name'])?></h1>
<?php if(($useMask['description']??'')!==''): ?><div class="panel"><?=nl2br(e((string)$useMask['description']))?></div><?php endif; ?>
<div class="panel">
<h2>Platzhalter ausfüllen</h2>
<?php if($maskPlaceholders===[]): ?><div class="muted">Diese Maske enthält keine Platzhalter.</div><?php else: ?>
<div class="placeholder-grid">
<?php foreach($maskPlaceholders as $placeholder): ?>
<div><label for="placeholder_<?=e(hash('sha256',$placeholder))?>"><?=e($placeholder)?></label><input id="placeholder_<?=e(hash('sha256',$placeholder))?>" data-placeholder="<?=e($placeholder)?>" autocomplete="off"></div>
<?php endforeach; ?>
</div>
<?php endif; ?>
</div>
<div class="actions" style="margin-bottom:14px"><button type="button" id="copyWorkflow">Gesamten Verlauf kopieren</button></div>
<div id="workflowPreview"></div>
<script id="maskData" type="application/json"><?=json_encode($useMask,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)?></script>
<?php else: ?>
<h1>Verfügbare Znuny-Masken</h1>
<div class="mask-list">
<?php foreach($data['masks'] as $mask): if(!($mask['published']??false)){continue;} ?>
<div class="mask-card">
<h3><?=e((string)($mask['name']??''))?></h3>
<p><?=e((string)($mask['description']??''))?></p>
<div class="muted"><?=count($mask['steps']??[])?> Schritte</div>
mask['id'])?>">Maske verwenden</a>
</div>
<?
