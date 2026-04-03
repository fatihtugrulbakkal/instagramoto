# 📸 Instagramoto

Bu proje, Instagram otomasyonu için geliştirilmiş bir web tabanlı yönetim panelidir. Kullanıcıların (admin ve müşteri olarak) giriş yapabildiği, istatistikleri (toplam müşteri, hesap sayısı, aktif görevler vb.) görüntüleyebildiği ve Instagram hesaplarını yönetebildiği bir arayüz sunar. React ile geliştirilen ön yüz, otomasyon görevlerini ve veri yönetimini gerçekleştirmek için bir arka uç API'si ile iletişim kurar.

## ✨ Özellikler

- **Kullanıcı Girişi:** Admin ve müşteri rolleri için ayrı giriş mekanizması.
- **İstatistik Paneli:** Toplam müşteri, hesap sayısı, aktif görevler gibi önemli metriklerin anlık takibi.
- **Hesap Yönetimi:** Instagram hesaplarını ekleme, silme ve yönetme.
- **Veri Havuzu Yönetimi:** Otomasyon için kullanılacak veri setlerini yönetme.
- **Otomatik DM Gönderme:** Belirlenen hesaplara otomatik direkt mesaj gönderme özelliği.
- **Şifre Yönetimi:** Güvenli şifre değiştirme ve yönetme.

## 💻 Teknoloji Yığını

![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Material-UI](https://img.shields.io/badge/Material--UI-0081CB?style=for-the-badge&logo=material-ui&logoColor=white)
![ApexCharts](https://img.shields.io/badge/ApexCharts-00E396?style=for-the-badge&logo=apexcharts&logoColor=white)

## 🚀 Kurulum

Projeyi yerel makinenizde çalıştırmak için aşağıdaki adımları izleyin:

1.  **Depoyu klonlayın:**
    ```sh
    git clone https://github.com/fatihtugrulbakkal/instagramoto.git
    cd instagramoto
    ```

2.  **Bağımlılıkları yükleyin:**
    ```sh
    npm install
    ```

3.  **Ortam değişkenlerini ayarlayın:**
    `.env` adında bir dosya oluşturun ve backend API adresinizi ekleyin:
    ```
    REACT_APP_API_URL=http://sizin-api-adresiniz.com
    ```

4.  **Geliştirme sunucusunu başlatın:**
    ```sh
    npm start
    ```
    Uygulama `http://localhost:3000` adresinde çalışacaktır.

## 📂 Proje Yapısı

```
frontend
├── .env
├── package.json
├── public
│   ├── index.html
│   └── manifest.json
└── src
    ├── App.js
    ├── index.js
    └── App.css
```

## 🤝 Katkıda Bulunma

Katkılarınız projeyi daha iyi hale getirecektir! Lütfen bir "pull request" açmaktan veya "issue" oluşturmaktan çekinmeyin.

1.  Projeyi "fork" edin.
2.  Yeni bir "branch" oluşturun (`git checkout -b ozellik/yeni-ozellik`).
3.  Değişikliklerinizi "commit" edin (`git commit -m 'Yeni bir özellik eklendi'`).
4.  "Branch"inizi "push" edin (`git push origin ozellik/yeni-ozellik`).
5.  Bir "Pull Request" açın.

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

## 📬 İletişim

Fatih Tuğrul Bakkal - fatihtugrulbakkal@gmail.com
