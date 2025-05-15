import React, { useState, useEffect } from 'react';
import './App.css';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from 'chart.js';

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend);

// API URLs
const API_GET_URL = "http://localhost:8080/emails";
const API_POST_URL = "http://localhost:8080/emails"; 
const API_GET_ALERT = "http://localhost:8080/alert";
const API_GET_DATA = "http://localhost:8080/get-data";

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
        "footer-text": "Network Anomaly Detection System © 2023 | Real-time Monitoring",
        "show-graphs": "Show Graphs",
        "hide-graphs": "Hide Graphs"
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
        "footer-text": "سیستەمی دۆزینەوەی شێوانەی تور © ٢٠٢٣ | چاودێری کاتێکی ڕاستەقینە",
        "show-graphs": "پیشاندانی گرافەکان",
        "hide-graphs": "شاردنەوەی گرافەکان"
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
        "footer-text": "نظام كشف الشذوذ في الشبكة © ٢٠٢٣ | المراقبة في الوقت الحقيقي",
        "show-graphs": "إظهار الرسوم البيانية",
        "hide-graphs": "إخفاء الرسوم البيانية"
    }
};

const NetworkDashboard = () => {
    const [showGraph, setShowGraph] = useState(false);
    const [language, setLanguage] = useState('en');
    const [networkData, setNetworkData] = useState({
        total_packets: 0,
        protocol_distribution: {},
        total_anomalies: 0,
        anomalies_by_type: {}
    });
    const [alertMessages, setAlertMessages] = useState({
        en: "Potential threat detected in your network. Please review traffic logs.",
        ku: "هێرشێکی گومانلێکراو دۆزرایەوە. تکایە ترافیکی تۆڕەکەت بپشکنە.",
        ar: "تم اكتشاف نشاط غير طبيعي. يرجى التحقق من سجلات الشبكة."
    });
    
    // Toggle graph visibility
    const toggleGraph = () => {
        setShowGraph(!showGraph);
    };

    // Change language
    const changeLanguage = (lang) => {
        setLanguage(lang);
        localStorage.setItem("selectedLanguage", lang);
    };

    // Fetch network data
    const fetchNetworkData = async () => {
        try {
            const response = await fetch(API_GET_DATA);
            if (!response.ok) throw new Error('Failed to fetch data');
            const data = await response.json();
            setNetworkData(data);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    // Fetch alert messages
    const fetchAlertMessages = async () => {
        try {
            const response = await fetch(API_GET_ALERT);
            if (!response.ok) throw new Error('Failed to fetch alerts');
            const alertData = await response.json();
            setAlertMessages(alertData);
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    };

    // Initialize data and set polling intervals
    useEffect(() => {
        // Load saved language
        const savedLanguage = localStorage.getItem("selectedLanguage") || "en";
        setLanguage(savedLanguage);
        
        // Fetch initial data
        fetchNetworkData();
        fetchAlertMessages();
        
        // Set up polling intervals
        const dataInterval = setInterval(fetchNetworkData, 2000);
        const alertInterval = setInterval(fetchAlertMessages, 5000);
        
        // Clean up intervals on unmount
        return () => {
            clearInterval(dataInterval);
            clearInterval(alertInterval);
        };
    }, []);

    // Format protocol distribution data for the chart
    const formatChartData = () => {
        const protocols = Object.keys(networkData.protocol_distribution || {});
        const counts = protocols.map(p => networkData.protocol_distribution[p]);
        
        // Generate colors based on number of protocols
        const colors = protocols.map((_, i) => {
            const baseColors = ['#36a2eb', '#ff6384', '#ffcd56', '#4bc0c0', '#9966ff', '#ff9f40'];
            return baseColors[i % baseColors.length];
        });
        
        return {
            labels: protocols,
            datasets: [
                {
                    label: translations[language]['protocol-distribution'],
                    data: counts,
                    backgroundColor: colors,
                }
            ]
        };
    };

    // Format anomalies data for chart
    const formatAnomalyChartData = () => {
        const attackTypes = {
            '1': 'Port Scanning',
            '2': 'DOS Attack',
            '3': 'Brute Force',
            '4': 'DNS Tunneling',
            'default': 'Other'
        };
        
        const anomalyTypes = Object.keys(networkData.anomalies_by_type || {});
        const labels = anomalyTypes.map(type => attackTypes[type] || attackTypes['default']);
        const counts = anomalyTypes.map(type => networkData.anomalies_by_type[type]);
        
        const colors = ['#ff6384', '#36a2eb', '#ffcd56', '#4bc0c0', '#9966ff'];
        
        return {
            labels,
            datasets: [
                {
                    label: translations[language]['anomalies'],
                    data: counts,
                    backgroundColor: colors,
                }
            ]
        };
    };

    // Determines if the alert message should be shown
    const shouldShowAlert = networkData.total_anomalies > 0;

    // Get translated text
    const getText = (key) => translations[language][key] || key;

    return (
        <div className="container">
            <div className="header">
                <a className="text-link" href="email.html">{getText('email-settings')}</a>
                <h1>{getText('title')}</h1>
                <div className="language-switcher">
                    <span onClick={() => changeLanguage('en')} className={language === 'en' ? 'active' : ''}>EN</span>
                    <span onClick={() => changeLanguage('ku')} className={language === 'ku' ? 'active' : ''}>KU</span>
                    <span onClick={() => changeLanguage('ar')} className={language === 'ar' ? 'active' : ''}>AR</span>
                </div>
            </div>

            {shouldShowAlert && (
                <div className="message">
                    <h2>⚠️ {getText('alert-title')} ⚠️</h2>
                    <p>{alertMessages[language]}</p>
                </div>
            )}

            <div className="instructions">
                <h2>{getText('welcome')}</h2>
                <p>{getText('intro')}</p>
                <p>{getText('email-notification')}</p>
                <p>{getText('explore-dashboard')}</p>
            </div>

            <div className="dashboard-container">
                <div className="metrics-row">
                    <div className="card">
                        <h3>{getText('packets')}</h3>
                        <div className="metric-value">{networkData.total_packets}</div>
                    </div>

                    <div className="card">
                        <h3>{getText('protocol-distribution')}</h3>
                        <div className="metric-details">
                            {Object.keys(networkData.protocol_distribution || {}).length > 0 ? (
                                Object.entries(networkData.protocol_distribution).map(([protocol, count], index) => (
                                    <p key={index}>{protocol}: {count}</p>
                                ))
                            ) : (
                                <p>Loading protocol data...</p>
                            )}
                        </div>
                    </div>
                </div>

                <div className="metrics-row">
                    <div className="card">
                        <h3>{getText('total-anomalies')}</h3>
                        <div className="metric-value">{networkData.total_anomalies}</div>
                    </div>

                    <div className="card">
                        <h3>{getText('anomalies')}</h3>
                        <div className="metric-details">
                            {Object.keys(networkData.anomalies_by_type || {}).length > 0 ? (
                                Object.entries(networkData.anomalies_by_type).map(([type, count], index) => {
                                    let attackType = "Unknown";
                                    switch(parseInt(type)) {
                                        case 1: attackType = "Port Scanning"; break;
                                        case 2: attackType = "DOS Attack"; break;
                                        case 3: attackType = "Brute Force"; break;
                                        case 4: attackType = "DNS Tunneling"; break;
                                        default: attackType = "Other";
                                    }
                                    return <p key={index}>{attackType}: {count}</p>;
                                })
                            ) : (
                                <p>No anomalies detected</p>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            <div style={{ textAlign: 'center', marginTop: '2rem' }}>
                <button onClick={toggleGraph} className="graph-button">
                    {showGraph ? getText('hide-graphs') : getText('show-graphs')}
                </button>
                
                {showGraph && (
                    <div className="graphs-container">
                        <div style={{ width: '500px', margin: '2rem auto' }}>
                            <h3>{getText('protocol-distribution')}</h3>
                            <Bar data={formatChartData()} />
                        </div>
                        
                        {networkData.total_anomalies > 0 && (
                            <div style={{ width: '500px', margin: '2rem auto' }}>
                                <h3>{getText('anomalies')}</h3>
                                <Bar data={formatAnomalyChartData()} />
                            </div>
                        )}
                    </div>
                )}
            </div>

            <footer>
                <p>{getText('footer-text')}</p>
            </footer>
        </div>
    );
};

export default NetworkDashboard;