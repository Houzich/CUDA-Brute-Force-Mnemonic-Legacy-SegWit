# Brute-force Mnemomonic Bitcoin on GPU(CUDA)  
## (Version 1.0)
## Генерация мнемонических фраз Bitcoin и соответствующих приватных ключей адресов m/0/x, m/1/x, m/0/0/x, m/0/1/x, m/44'/0'/0'/0/x, m/44'/0'/0'/1/x, m/84'/0'/0'/0/x, m/84'/0'/0'/1/x. Поиск адресов в базе.
![](image/Screenshot_1.png)

## Файл config.cfg
 * ***"folder_database_legacy": "F:\\database_legacy"***  - путь к папке с таблицами адресов Bitcoin Legacy(BIP32, BIP44). Адреса в таблицах должны быть в формате hash160 и отсортированы программой https://github.com/Houzich/Convert-Addresses-To-Hash160-For-Brute-Force.
* ***"folder_database_segwit": "F:\\database_segwit"***  - путь к папке с таблицами адресов Bitcoin Native SegWit(BIP84). Адреса в таблицах должны быть в формате hash160 и отсортированы программой https://github.com/Houzich/Convert-Addresses-To-Hash160-For-Brute-Force.
* ***"cuda_grid": 1024*** - настройка под видеокарту.
* ***"cuda_block": 256*** - настройка под видеокарту.
Кол-во генерируемых мнемоник за раунд равно cuda_grid*cuda_block.


## Описание
При запуске программы, считываются настройки из файла config.cfg.
В консоли выводится надпись
> *Detected 3 CUDA Capable device(s)*

где число 3  - это количество найденных видеокарт NVIDIA.
Далее выводятся характеристики каждой карты:
> *Device 0: "NVIDIA GeForce GTX 1050 Ti"*

> *...*

> *Device 1: "NVIDIA GeForce GTX 1050 Ti"*

> *Enter the number of the used video card:*

Начинается считывание и преобразование файлов баз с адресами:
> *PROCESSED 2168134 ROWS IN FILE F:\\database\A0.csv*
> *.....*

Где 2168134 - это кол-во адресов в файле. Адреса в файле хранятся в 20 байтовом формате hash160 в виде hex-строки. И отсортированы по возрастанию.

> *Enter number of generate mnemonic:*

Общее кол-во мнемоник которое мы хотим генерировать. Это введено для проверки скорости генерации или для сохранения результатов генерации в файлы. Если хотим бесконечно, то устанавливаем максимальное значение 18000000000000000000.

> *Enter num rounds save data in file:*

Какое кол-во раундов мы хотим записывать в файл. Кол-во генерируемых мнемоник за раунд равно cuda_grid*cuda_block. Введено для проверки правильности генерации. Мнемоника и соответствующие ей адреса записываются в файл Save_Addresses.csv
Запись производится очень медленно. Так как преобразование 20-ти байтного формата в формат "читаемый" производится на ЦПУ. При основной работе программы выбирать кол-во циклов 0.

> *Enter num bytes for check 6...8: :*


Можно ввести количество байт по которым будет производиться дополнительная сверка. Чтоб пропустить этот шаг нужно ввести 0.
Если ввести число(6...8), то адреса будут проверяться на совпадение еще и по заданному количеству байт.

Далее выводится кол-во кошельков генерируемых за раунд. И начинается процесс генерации.
В ходе работы программы, постоянно обновляется надпись

> *SPEED:    1,819 MNEMONICS/SECOND AND 72,789 ADDRESSES/SECOND, ROUND: 0*

Кол-во мнемоник и кол-во адресов генерируемых за секунду. В данном случае, для каждого сгенерированного кошелька генерировалось 40 адресов *(5 адресов патча m/0/x, 5 адресов патча m/1/x, 5 адресов патча m/0/0/x, 5 адресов патча m/0/1/x, 5 адресов патча m/44'/0'/0'/0/x, 5 адресов патча m/44'/0'/0'/0/x, 5 адресов патча m/84'/0'/0'/0/x и 5 адресов патча m/84'/0'/0'/1/x)*

# Проверка на совпадение по байтам
Если в пункте 5 ввести, к примеру, 5. То периодически на экране будут появляться надписи такого формата:

> *!!!FOUND SEGWIT BYTES: mean negative bounce charge correct improve shaft moral helmet border grocery giggle,bc1qg2ex46ju3mf0ntycmzm0z2uu8e35gyl00cjq8w,bc1qg2ex46juygvzgme2jaxjp9jguhjrqdkjh8xdlj,42B26AEA5C8ED2F9AC98D8B6F12B9C3E634413EF,42B26AEA5C2218246F2A974D209648E5E43036D2*

Мнемоника сгенерированного кошелька. Его адрес. Адрес в базе, который совпал по первым байтам с адресом мнемоники. И соответственно их представление в 20-и байтовом формате. Можно посчитать одинаковые байты и убедиться в этом.
Все эти адреса сохраняются в лог-файл Found_Bytes.csv.
В файле, строки хранятся в виде:</br>
*mean negative bounce charge correct improve shaft moral helmet border grocery giggle,bc1qg2ex46ju3mf0ntycmzm0z2uu8e35gyl00cjq8w,bc1qg2ex46juygvzgme2jaxjp9jguhjrqdkjh8xdlj,42B26AEA5C8ED2F9AC98D8B6F12B9C3E634413EF,42B26AEA5C2218246F2A974D209648E5E43036D2,Sun Apr  2 22:16:46 2023*



# Если нашли кошелек
В консоли появиться надписи:
> * !!!FOUND!!!</br>
!!!FOUND!!!</br>
!!!FOUND!!!</br>
!!!FOUND!!!</br>
!!!FOUND SEGWIT: chicken jewel keen arm artefact disorder gravity claim sick female verb faint, 0x92F96C980AA87A1580961851A0EF93B578EAFFB8</br>
!!!FOUND!!!</br>
!!!FOUND!!!</br>
!!!FOUND!!!</br>
!!!FOUND!!!*

Соответственно мнемоника и адрес который мы нашли. И информация добавиться в файл Found_Addresses.csv.
В файле строки хранятся в виде:</br>
*chicken jewel keen arm artefact disorder gravity claim sick female verb faint, 1Q4Qgk9pftrXRna1LETwcHXuoKJVrKSfm,Sun Apr  2 12:51:42 2023*

## Файл BruteForceMnemonicBitcoinV10.exe находится в папке exe



### ОБСУЖДЕНИЕ КОДА: https://t.me/BRUTE_FORCE_CRYPTO_WALLET