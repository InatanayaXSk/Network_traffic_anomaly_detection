// API URLs
const API_GET_URL = "http://localhost:8080/emails";
const API_POST_URL = "http://localhost:8080/emails"; 
const API_GET_ALERT = "http://localhost:8080/alert";
const API_GET_DATA = "http://localhost:8080/get-data";

let emailList = [];
let englishAlertInst = "";
let kurdishAlertInst = "";
let arabicAlertInst = "";

// Translation data
const translations = {
    en: {
        "email-settings": "Email Settings",
        "title": "Network Anomaly Detection System",
        "welcome": "Welcome to the Home Network Traffic Anomaly Detection System",
        "intro": "This system is designed to ensure the security and reliability of your home network.",
        "email-notification": "Anomalies trigger email notifications with attack details.",
        "explore-dashboard": "Explore the dashboard to view network metrics and anomalies.",
        "packets": "Packets",
        "protocol-distribution": "Protocol Distribution",
        "total-anomalies": "Total Anomalies",
        "anomalies": "Anomalies by Type",
        "alert-title": "Anomaly Detected!",
        "footer-text": "Network Anomaly Detection System © 2023 | Real-time Monitoring"
    },
    ku: {
        "email-settings": "ڕێکخستنەکانی ئیمەیڵ",
        "title": "سیستەمی دۆزینەوەی ڕەفتارە نائاساییەکانی تۆڕ",
        "welcome": "بەخێربێن بۆ سیستەمی چاودێری ڕەفتارە نائاساییەکانی تۆڕی ماڵەوە",
        "intro": "ئەم سیستەمە بۆ پاراستن و دڵنیایی تۆڕی ماڵەوەت داڕێژراوە.",
        "email-notification": "شێوەنەماویەکان ئاگادارکردنەوەی ئیمەیڵ دەکەنەوە لەگەڵ وردەکاری هێرشەکە.",
        "explore-dashboard": "پانێڵی بەڕێوەبەری بکەوە بۆ بینینی پێوەرەکانی تۆڕ و شێوەنەماویەکان.",
        "packets": "پاکێتەکان",
        "protocol-distribution": "دابەشبوونی جۆرەکانی پەیوەندی",
        "total-anomalies": "کۆی ڕەفتارە گومانلێکراوەکان",
        "anomalies": "جۆرەکانی ڕەفتارە گومانلێکراوەکان",
        "alert-title": "شێوەنەماوی دۆزرایەوە!",
        "footer-text": "سیستەمی دۆزینەوەی شێوانەی تور © ٢٠٢٣ | چاودێری کاتێکی ڕاستەقینە"
    },
    ar: {
        "email-settings": "إعدادات البريد الإلكتروني",
        "title": "نظام كشف الأنشطة الغير طبيعية في الشبكة",
        "welcome": "أهلاً بك في نظام مراقبة الأنشطة غير العادية في شبكة المنزل",
        "intro": "تم تطوير هذا النظام لحماية شبكة المنزل وضمان أمنها.",
        "email-notification": "تؤدي الحالات الشاذة إلى إشعارات البريد الإلكتروني مع تفاصيل الهجوم.",
        "explore-dashboard": "تصفح لوحة المعلومات لعرض مقاييس الشبكة والحالات الشاذة.",
        "packets": "الحزم",
        "protocol-distribution": "توزيع أنواع الاتصالات",
        "total-anomalies": "إجمالي الأنشطة المشبوهة",
        "anomalies": "نوع الأنشطة المشبوهة",
        "alert-title": "تم اكتشاف شذوذ!",
        "footer-text": "نظام كشف الشذوذ في الشبكة © ٢٠٢٣ | المراقبة في الوقت الحقيقي"
    }
};

// Change language function
function changeLanguage(lang) {
    localStorage.setItem("selectedLanguage", lang);
    document.querySelectorAll("[data-key]").forEach(element => {
        const key = element.getAttribute("data-key");
        if (translations[lang] && translations[lang][key]) {
            element.textContent = translations[lang][key];
        }
    });
    updateAlertMessage();
}

// Update alert message based on language
function updateAlertMessage() {
    const messageElement = document.querySelector('.message p');
    if (messageElement) {
        const currentLang = localStorage.getItem("selectedLanguage") || "en";
        switch(currentLang) {
            case 'ku':
                messageElement.textContent = kurdishAlertInst;
                break;
            case 'ar':
                messageElement.textContent = arabicAlertInst;
                break;
            default:
                messageElement.textContent = englishAlertInst;
        }
    }
}

// Toggle alert message visibility
function toggleMessage(show) {
    const messageElement = document.querySelector('.message');
    if (messageElement) {
        messageElement.style.display = show ? 'block' : 'none';
    }
}

// Fetch anomaly data
async function fetchAnomalyData() {
    try {
        const response = await fetch(API_GET_DATA);
        if (!response.ok) throw new Error('Failed to fetch data');
        const data = await response.json();
        updateUI(data);
        toggleMessage(data.total_anomalies > 0);
    } catch (error) {
        console.error("Error fetching data:", error);
    }
}

// Load alert instructions
async function loadAlertInstructions() {
    try {
        const response = await fetch(API_GET_ALERT);
        if (!response.ok) throw new Error('Failed to fetch alerts');
        const alertData = await response.json();
        englishAlertInst = alertData['en'];
        kurdishAlertInst = alertData['ku'];
        arabicAlertInst = alertData['ar'];
        updateAlertMessage();
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

// Update UI with data
function updateUI(data) {
    // Update Total Packets
    const totalPacketsElement = document.getElementById("total-packets");
    if (totalPacketsElement) totalPacketsElement.textContent = data.total_packets || 0;

    // Update Protocol Distribution
    const protocolDetails = document.getElementById("protocol-details");
    if (protocolDetails) {
        protocolDetails.innerHTML = "";
        if (data.protocol_distribution) {
            for (const [protocol, count] of Object.entries(data.protocol_distribution)) {
                const detail = document.createElement("p");
                detail.textContent = `${protocol}: ${count}`;
                protocolDetails.appendChild(detail);
            }
        }
    }

    // Update Total Anomalies
    const totalAnomaliesElement = document.getElementById("total-anomalies");
    if (totalAnomaliesElement) totalAnomaliesElement.textContent = data.total_anomalies || 0;

    // Update Anomalies Details
    const anomaliesDetails = document.getElementById("anomalies-details");
    if (anomaliesDetails) {
        anomaliesDetails.innerHTML = "";
        if (data.anomalies_by_type) {
            for (const [type, count] of Object.entries(data.anomalies_by_type)) {
                const detail = document.createElement("p");
                let attackType = "Unknown";
                switch(parseInt(type)) {
                    case 1: attackType = "Port Scanning"; break;
                    case 2: attackType = "DOS Attack"; break;
                    case 3: attackType = "Brute Force"; break;
                    case 4: attackType = "DNS Tunneling"; break;
                    default: attackType = "Other";
                }
                detail.textContent = `${attackType}: ${count}`;
                anomaliesDetails.appendChild(detail);
            }
        }
    }
}

// Initialize application
document.addEventListener("DOMContentLoaded", () => {
    // Set initial language
    const savedLanguage = localStorage.getItem("selectedLanguage") || "en";
    changeLanguage(savedLanguage);
    
    // Start data polling
    fetchAnomalyData();
    loadAlertInstructions();
    setInterval(fetchAnomalyData, 2000);
    setInterval(loadAlertInstructions, 5000);
});

function loadEmails() {
    // Only run this code on the email page
    if (!document.querySelector('.email-list')) return;
    
    fetch(API_GET_URL)
        .then(response => response.json())
        .then(data => {
            const emailList = document.querySelector('.email-list');
            emailList.innerHTML = '';
            
            if (data.emails && data.emails.length > 0) {
                data.emails.forEach(email => {
                    const emailElement = document.createElement('div');
                    emailElement.classList.add('email-item');
                    
                    const emailText = document.createElement('span');
                    emailText.textContent = email;
                    
                    const deleteButton = document.createElement('span');
                    deleteButton.textContent = '✖';
                    deleteButton.classList.add('delete-btn');
                    deleteButton.onclick = function() {
                        emailElement.remove();
                    };
                    
                    emailElement.appendChild(emailText);
                    emailElement.appendChild(deleteButton);
                    emailList.appendChild(emailElement);
                });
            } else {
                const noEmails = document.createElement('p');
                noEmails.textContent = 'No emails configured';
                emailList.appendChild(noEmails);
            }
        })
        .catch(error => {
            console.error('Error loading emails:', error);
            const emailList = document.querySelector('.email-list');
            emailList.innerHTML = '<p>Error loading emails</p>';
        });
}

function AddEmail() {
    const emailList = document.querySelector('.email-list');
    const emailInput = document.createElement('input');
    emailInput.type = 'email';
    emailInput.placeholder = 'Enter email address';
    emailInput.classList.add('email-input');
    emailList.appendChild(emailInput);
    emailInput.focus();
}

function saveEmailList() {
    const emailItems = document.querySelectorAll('.email-item span:first-child');
    const emailInput = document.querySelector('.email-input');
    const emails = Array.from(emailItems).map(item => item.textContent);
    
    // Add the new email if it exists
    if (emailInput && emailInput.value.trim() !== '') {
        const newEmail = emailInput.value.trim();
        
        // Send just the new email to the server
        fetch(API_POST_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email: newEmail }),
        })
        .then(response => {
            if (response.ok) {
                // Reload the email list
                loadEmails();
            } else {
                console.error('Failed to save email');
            }
        })
        .catch(error => {
            console.error('Error saving email:', error);
        });
    } else {
        // Just reload the list if no new email
        loadEmails();
    }
}

function cancelEditing() {
    const emailInput = document.querySelector('.email-input');
    if (emailInput) {
        emailInput.remove();
    }
}

// Initialize email page if we are on that page
document.addEventListener("DOMContentLoaded", () => {
    // Set initial language
    const savedLanguage = localStorage.getItem("selectedLanguage") || "en";
    changeLanguage(savedLanguage);
    
    // Start data polling
    fetchAnomalyData();
    loadAlertInstructions();
    setInterval(fetchAnomalyData, 2000);
    setInterval(loadAlertInstructions, 5000);
    
    // Load emails if on email page
    loadEmails();
});

