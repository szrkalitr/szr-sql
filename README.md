szr-sql

SQL injection analiz aracı. Go ile geliştirilmiştir.

Özellikler

- Boolean-based SQL injection tespiti
- Time-based SQL injection tespiti
- DBMS fingerprinting
- MySQL, PostgreSQL, MSSQL ve SQLite profilleri
- Veritabanı listeleme
- Tablo listeleme
- Kolon listeleme
- Yetkili test ortamlarında veri çıkarımı
- GET ve POST desteği
- Cookie desteği
- Özel parametre seçimi
- Çoklu iş parçacığı (Threads)
- Rate limit algılama
- İstek zaman aşımı kontrolü
- Ayrıntılı terminal çıktısı
- JSON, TXT ve Markdown raporlama

Komutlar

Komut| Açıklama
"scan"| Zafiyet tespiti
"dbs"| Veritabanlarını listeleme
"tables"| Tabloları listeleme
"columns"| Kolonları listeleme
"dump"| Test verilerini görüntüleme
"all"| Otomatik analiz

Derleme

Go 1.20 veya üzeri:

go build -o szr-sql .

Windows:

go build -o szr-sql.exe .

Kullanım

./szr-sql help

Lisans ve Kullanım

Educational use only.

Yalnızca izin verilen sistemlerde ve kontrollü laboratuvar ortamlarında kullanılması amaçlanmıştır.
