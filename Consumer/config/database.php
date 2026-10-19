<?php
return ['default'=>'pgsql','connections'=>['pgsql'=>['driver'=>'pgsql','host'=>'product-db','port'=>5432,'database'=>'otherwise','username'=>'otherwise','password'=>env('DB_PASSWORD'),'charset'=>'utf8','prefix'=>'','schema'=>'public','sslmode'=>'prefer']]];
