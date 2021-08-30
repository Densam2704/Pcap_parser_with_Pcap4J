# Pcap parser with Pcap4J

## Назначение

_Pcap parser with Pcap4J_ является частью выпускной квалификационной работы по теме "Исследование трафика в беспроводной сети".

Программа _Pcap parser with Pcap4j_ предназначена для того, чтобы получить некоторые характеристики трафика из файлов PCAP захваченного трафика с использованием
библиотеки [Pcap4j](https://github.com/kaitoy/pcap4j) парсинга PCAP файлов .

<a href="https://ibb.co/mDWx8GS"><img src="https://i.ibb.co/X2Rw8bV/Diploma-apps.png" alt="Diploma-apps" border="0"></a>

Полученные характеристики записываются в отдельные файлы, которые в дальнейшем используются другим приложением.


Написана на языке Java с использованием находящейся в свободном доступе библиотеки Pcap4j для работы с PCAP файлами.

## Сессии и мультимедиа сессии

<a href="https://ibb.co/kJBYfCP"><img src="https://i.ibb.co/pQwC8Fk/MMsession-and-session.png" alt="MMsession-and-session" border="0"></a>

Обычная сессия (или коротко сессия) представляет собой структуру, в которой содержатся пары _ip:port_, однозначно идентифицирующие эту сессию. Первая пара _ip1:port1_ относится к сети исследовательского стенда. Вторая пара _ip2:port2_ описывает некую внешнюю сеть, с которой идет обмен данными

Мультимедиа сессия объединяет в себе трафик по IP-адресам и относится к какому-либо мультимедиа приложению. Чтобы определить к какому приложению относятся мультимедийные сессии, необходимо заранее экспериментально узнать, какие IP-адреса использует то или иное приложение. 

В работе выделялись мультимедиа сессии приложений Discord и Telegram.


## Задача обработки файлов трафика
В указанной директории имеется множество файлов с захваченным трафиком формата PCAP.

Файл трафика состоит из множества пакетов.
Пакеты трафика представляют из себя многоуровневую вложенную структуру с заголовками.
Каждому пакету ставится в соответствие время захвата пакета. 

Пример структуры пакета:

<a href="https://imgbb.com/"><img src="https://i.ibb.co/tDhpznJ/packet.png" alt="packet" border="0"></a>

Необходимо было:
1) Выделить все сессии (ip1:port1, ip2:port2) и мультимедиа сессии (ip1,ip2);

2) Для каждой сессии и мультимедиа сессии получить исследуемые характеристики;

3) Результаты экспортировать в произвольный файл (возможно несколько файлов).


## Характеристики трафика, получаемые Pcap parser with Pcap4J :

   
 + Продолжительность сессии/мультимедиа сессии
  
 + Интервал поступления пакетов сессии/мультимедиа сессии

 + Размер сетевых пакетов в сессии/мультимедиа сессии


  
 





