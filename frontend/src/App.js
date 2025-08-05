import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
    createTheme, ThemeProvider, CssBaseline, Box, Grid, Paper, Typography, 
    Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Toolbar,
    Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    TextField, Button, CircularProgress, IconButton, Stack,
    Container, Tooltip, Chip, Alert, Dialog, DialogActions, DialogContent, DialogTitle, Avatar,
    Select, MenuItem, FormControl, InputLabel, LinearProgress, Skeleton, Divider, ToggleButtonGroup, ToggleButton,
    FormControlLabel, Switch
} from '@mui/material';
// İkonlar
import DashboardIcon from '@mui/icons-material/Dashboard';
import PeopleAltIcon from '@mui/icons-material/PeopleAlt';
import StorageIcon from '@mui/icons-material/Storage';
import SendIcon from '@mui/icons-material/Send';
import WhatsAppIcon from '@mui/icons-material/WhatsApp';
import EmailIcon from '@mui/icons-material/Email';
import SettingsIcon from '@mui/icons-material/Settings';
import GroupIcon from '@mui/icons-material/Group';
import LogoutIcon from '@mui/icons-material/Logout';
import DeleteIcon from '@mui/icons-material/Delete';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import EditIcon from '@mui/icons-material/Edit';
import GroupAddIcon from '@mui/icons-material/GroupAdd';
import DataSaverOnIcon from '@mui/icons-material/DataSaverOn';
import SupervisedUserCircleIcon from '@mui/icons-material/SupervisedUserCircle';
import AccountBoxIcon from '@mui/icons-material/AccountBox';
import DonutLargeIcon from '@mui/icons-material/DonutLarge';
import SaveIcon from '@mui/icons-material/Save';
import ArticleIcon from '@mui/icons-material/Article';
import LocalFireDepartmentIcon from '@mui/icons-material/LocalFireDepartment';
import PasswordIcon from '@mui/icons-material/Password';
import HistoryIcon from '@mui/icons-material/History';
import HealthAndSafetyIcon from '@mui/icons-material/HealthAndSafety';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import CookieIcon from '@mui/icons-material/Cookie';
import FavoriteIcon from '@mui/icons-material/Favorite';
import TagIcon from '@mui/icons-material/Tag';
import SyncIcon from '@mui/icons-material/Sync'; // YENİ

import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3002/api';

const getErrorMessage = async (response) => {
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("application/json") !== -1) {
        const errData = await response.json();
        return errData.message || 'Bilinmeyen bir sunucu hatası oluştu.';
    } else {
        return "Sunucudan beklenmeyen bir cevap alındı. API sunucusunun çalıştığından emin olun.";
    }
};

const getTheme = (mode) => createTheme({ /* Tema ayarları burada olabilir */ });
const drawerWidth = 260;

// ====================================================================
// --- YARDIMCI BİLEŞENLER ---
// ====================================================================

function KpiCard({ title, value, icon, loading }) {
    return (
        <Paper sx={{ p: 2, display: 'flex', alignItems: 'center', height: '100%' }}>
            <Avatar sx={{ bgcolor: 'primary.main', color: 'white', width: 56, height: 56, mr: 2 }}>
                {icon}
            </Avatar>
            <Box>
                <Typography color="text.secondary" gutterBottom>{title}</Typography>
                {loading ? (
                    <Skeleton variant="text" width={40} />
                ) : (
                    <Typography component="p" variant="h4" fontWeight="bold">
                        {value ?? 0}
                    </Typography>
                )}
            </Box>
        </Paper>
    );
}


// ====================================================================
// --- SAYFA BİLEŞENLERİ ---
// ====================================================================

function LoginPage({ onLoginSuccess }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleLogin = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        try {
            if (!API_URL) {
                throw new Error("API adresi yapılandırılmamış. Lütfen .env dosyasını kontrol edin.");
            }
            const response = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (!response.ok) {
                const message = await getErrorMessage(response);
                throw new Error(message);
            }
            const data = await response.json();
            onLoginSuccess(data.token, data.role, data.name);
        } catch (err) {
            if (err instanceof TypeError) {
                setError('Sunucuya ulaşılamıyor. Backend sunucusunun çalıştığından emin olun.');
            } else {
                setError(err.message);
            }
        }
        setIsLoading(false);
    };

    return (
        <Container component="main" maxWidth="xs">
            <CssBaseline />
            <Box sx={{ marginTop: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <Typography component="h1" variant="h5"> Yönetim Paneli </Typography>
                <Box component="form" onSubmit={handleLogin} noValidate sx={{ mt: 1 }}>
                    <TextField margin="normal" required fullWidth label="Kullanıcı Adı" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} />
                    <TextField margin="normal" required fullWidth label="Şifre" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    {error && <Alert severity="error" sx={{ mt: 2, width: '100%' }}>{error}</Alert>}
                    <Button type="submit" fullWidth variant="contained" sx={{ mt: 3, mb: 2 }} disabled={isLoading}>
                        {isLoading ? <CircularProgress size={24} /> : 'Giriş Yap'}
                    </Button>
                </Box>
            </Box>
        </Container>
    );
}

function AdminDashboardPage({ authedFetch }) {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchStats = async () => {
            setLoading(true);
            try {
                const res = await authedFetch(`${API_URL}/dashboard/stats`);
                const data = await res.json();
                if (data.success) {
                    setStats(data.stats);
                }
            } catch (error) {
                console.error("Admin istatistikleri alınamadı:", error);
            }
            setLoading(false);
        };
        fetchStats();
    }, [authedFetch]);

    return (
        <Grid container spacing={3}>
            <Grid item xs={12} sm={6} md={4}>
                <KpiCard title="Toplam Müşteri" value={stats?.clientsCount} icon={<SupervisedUserCircleIcon />} loading={loading} />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
                <KpiCard title="Toplam Hesap" value={stats?.accountsCount} icon={<AccountBoxIcon />} loading={loading} />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
                <KpiCard title="Aktif İşlemler" value={stats?.activeJobs} icon={<DonutLargeIcon />} loading={loading} />
            </Grid>
        </Grid>
    );
}

function ClientDashboardPage({ authedFetch }) {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchStats = async () => {
            setLoading(true);
            try {
                const res = await authedFetch(`${API_URL}/dashboard/stats`);
                const data = await res.json();
                if (data.success) {
                    setStats(data.stats);
                }
            } catch (error) {
                console.error("Müşteri istatistikleri alınamadı:", error);
            }
            setLoading(false);
        };
        fetchStats();
    }, [authedFetch]);

    return (
        <Grid container spacing={3}>
            <Grid item xs={12} sm={6} md={4}>
                <KpiCard title="Hesaplarım" value={stats?.myAccountsCount} icon={<PeopleAltIcon />} loading={loading} />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
                <KpiCard title="Veri Havuzu" value={stats?.dataPoolCount} icon={<StorageIcon />} loading={loading} />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
                <KpiCard title="Bugün Gönderilen DM" value={stats?.dmsSentToday} icon={<SendIcon />} loading={loading} />
            </Grid>
        </Grid>
    );
}

function AdminSettingsPage() { return <Paper><Typography>Genel Ayarlar (Yakında)</Typography></Paper>; }

function ClientSettingsPage({ authedFetch }) {
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [message, setMessage] = useState({ type: '', text: '' });
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleChangePassword = async (e) => {
        e.preventDefault();
        if (newPassword !== confirmPassword) {
            setMessage({ type: 'error', text: 'Yeni şifreler eşleşmiyor.' });
            return;
        }
        setIsSubmitting(true);
        setMessage({ type: '', text: '' });
        try {
            await authedFetch(`${API_URL}/client/change-password`, {
                method: 'PUT',
                body: JSON.stringify({ currentPassword, newPassword })
            });
            setMessage({ type: 'success', text: 'Şifreniz başarıyla güncellendi.' });
            setCurrentPassword('');
            setNewPassword('');
            setConfirmPassword('');
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
        setIsSubmitting(false);
    };

    return (
        <Paper sx={{ p: 4, maxWidth: 600 }}>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 3 }}>
                <Avatar sx={{ bgcolor: 'secondary.main', color: 'white' }}><PasswordIcon /></Avatar>
                <Typography variant="h5">Şifre Değiştir</Typography>
            </Stack>
            <Box component="form" onSubmit={handleChangePassword}>
                <Stack spacing={3}>
                    <TextField
                        label="Mevcut Şifre"
                        type="password"
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        required
                        fullWidth
                    />
                    <TextField
                        label="Yeni Şifre"
                        type="password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        required
                        fullWidth
                    />
                    <TextField
                        label="Yeni Şifre (Tekrar)"
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        fullWidth
                    />
                    <Button type="submit" variant="contained" disabled={isSubmitting} sx={{ alignSelf: 'flex-start' }}>
                        {isSubmitting ? <CircularProgress size={24} /> : 'Şifreyi Güncelle'}
                    </Button>
                </Stack>
            </Box>
            {message.text && <Alert severity={message.type} sx={{ mt: 3 }}>{message.text}</Alert>}
        </Paper>
    );
}

function AdminClientsPage({ authedFetch }) {
    const [clients, setClients] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [message, setMessage] = useState({ type: '', text: '' });
    const [newClientName, setNewClientName] = useState('');
    const [newClientUsername, setNewClientUsername] = useState('');
    const [newClientPassword, setNewClientPassword] = useState('');
    const [newClientLimit, setNewClientLimit] = useState('5');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [isEditDialogOpen, setEditDialogOpen] = useState(false);
    const [editingClient, setEditingClient] = useState(null);

    const fetchClients = useCallback(async () => {
        setIsLoading(true);
        try {
            const response = await authedFetch(`${API_URL}/admin/clients`);
            const data = await response.json();
            if (data.success) {
                setClients(data.clients);
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            setMessage({ type: 'error', text: `Müşteriler yüklenemedi: ${error.message}` });
        }
        setIsLoading(false);
    }, [authedFetch]);

    useEffect(() => { fetchClients(); }, [fetchClients]);

    const handleAddClient = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setMessage({ type: '', text: '' });
        try {
            await authedFetch(`${API_URL}/admin/clients`, {
                method: 'POST',
                body: JSON.stringify({ clientName: newClientName, username: newClientUsername, password: newClientPassword, maxAccounts: newClientLimit })
            });
            setMessage({ type: 'success', text: 'Müşteri başarıyla oluşturuldu.' });
            setNewClientName(''); setNewClientUsername(''); setNewClientPassword(''); setNewClientLimit('5');
            fetchClients();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
        setIsSubmitting(false);
    };

    const handleOpenEditDialog = (client) => {
        setEditingClient(JSON.parse(JSON.stringify(client)));
        setEditDialogOpen(true);
    };

    const handleCloseEditDialog = () => {
        setEditDialogOpen(false);
        setEditingClient(null);
    };

    const handleUpdateClient = async () => {
        if (!editingClient) return;
        try {
            await authedFetch(`${API_URL}/admin/clients/${editingClient.id}`, {
                method: 'PUT',
                body: JSON.stringify({
                    clientName: editingClient.clientName,
                    maxAccounts: editingClient.limits.maxAccounts
                })
            });
            setMessage({ type: 'success', text: 'Müşteri bilgileri güncellendi.' });
            handleCloseEditDialog();
            fetchClients();
        } catch (error) {
            setMessage({ type: 'error', text: `Güncelleme hatası: ${error.message}` });
        }
    };

    const handleDeleteClient = async (clientId, clientName) => {
        if (!window.confirm(`'${clientName}' müşterisini silmek istediğinizden emin misiniz?`)) return;
        setMessage({ type: '', text: '' });
        try {
            const response = await authedFetch(`${API_URL}/admin/clients/${clientId}`, { method: 'DELETE' });
            const data = await response.json();
            setMessage({ type: 'success', text: data.message || 'Müşteri başarıyla silindi.' });
            fetchClients();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
    };

    return (
        <>
            <Grid container spacing={4}>
                <Grid item xs={12} lg={4}>
                    <Paper>
                        <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 3 }}>
                            <Avatar sx={{ bgcolor: 'primary.light', color: 'primary.main' }}><GroupAddIcon /></Avatar>
                            <Typography variant="h6">Yeni Müşteri Oluştur</Typography>
                        </Stack>
                        <Box component="form" onSubmit={handleAddClient}>
                            <Stack spacing={2}>
                                <TextField label="Müşteri Adı Soyadı" value={newClientName} onChange={e => setNewClientName(e.target.value)} fullWidth required />
                                <TextField label="Müşteri Giriş Adı" value={newClientUsername} onChange={e => setNewClientUsername(e.target.value)} fullWidth required />
                                <TextField label="Şifre" type="password" value={newClientPassword} onChange={e => setNewClientPassword(e.target.value)} fullWidth required />
                                <TextField label="Maks. Hesap Limiti" type="number" value={newClientLimit} onChange={e => setNewClientLimit(e.target.value)} fullWidth required />
                                <Button type="submit" variant="contained" fullWidth disabled={isSubmitting}>
                                    {isSubmitting ? <CircularProgress size={24} /> : 'Müşteriyi Oluştur'}
                                </Button>
                            </Stack>
                        </Box>
                    </Paper>
                </Grid>
                <Grid item xs={12} lg={8}>
                    <Paper>
                        <Typography variant="h6" gutterBottom>Mevcut Müşteriler</Typography>
                        {message.text && (<Alert severity={message.type} sx={{ my: 2 }} onClose={() => setMessage({ text: '' })}>{message.text}</Alert>)}
                        {isLoading ? <CircularProgress /> : (
                            <TableContainer>
                                <Table>
                                    <TableHead sx={{ bgcolor: 'action.hover' }}>
                                        <TableRow>
                                            <TableCell>Ad Soyad</TableCell>
                                            <TableCell>Kullanıcı Adı</TableCell>
                                            <TableCell align="center">Hesap Limiti</TableCell>
                                            <TableCell align="right">İşlemler</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {clients.map(client => (
                                            <TableRow key={client.id} hover sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                                                <TableCell component="th" scope="row">{client.clientName}</TableCell>
                                                <TableCell><Chip label={client.username} size="small" /></TableCell>
                                                <TableCell align="center"><Typography fontWeight="bold">{client.limits?.maxAccounts || 'N/A'}</Typography></TableCell>
                                                <TableCell align="right">
                                                    <Tooltip title="Müşteriyi Düzenle"><IconButton color="primary" onClick={() => handleOpenEditDialog(client)}><EditIcon /></IconButton></Tooltip>
                                                    <Tooltip title="Müşteriyi Sil"><IconButton color="error" onClick={() => handleDeleteClient(client.id, client.clientName)}><DeleteIcon /></IconButton></Tooltip>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </TableContainer>
                        )}
                    </Paper>
                </Grid>
            </Grid>
            <Dialog open={isEditDialogOpen} onClose={handleCloseEditDialog}>
                <DialogTitle>Müşteri Bilgilerini Düzenle</DialogTitle>
                <DialogContent>
                    {editingClient && (
                        <Stack spacing={3} sx={{ mt: 2, width: '350px' }}>
                            <TextField label="Müşteri Adı Soyadı" value={editingClient.clientName} onChange={(e) => setEditingClient({ ...editingClient, clientName: e.target.value })} fullWidth/>
                            <TextField label="Maksimum Hesap Limiti" type="number" value={editingClient.limits.maxAccounts} onChange={(e) => setEditingClient({ ...editingClient, limits: { ...editingClient.limits, maxAccounts: e.target.value } })} fullWidth/>
                        </Stack>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseEditDialog}>İptal</Button>
                    <Button onClick={handleUpdateClient} variant="contained">Kaydet</Button>
                </DialogActions>
            </Dialog>
        </>
    );
}

function HesaplarPage({ accounts, authedFetch, onUpdate }) {
    const [loginMethod, setLoginMethod] = useState('password');
    const [newUsername, setNewUsername] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [cookieUsername, setCookieUsername] = useState('');
    const [cookieValue, setCookieValue] = useState('');
    const [isSubmittingCookie, setIsSubmittingCookie] = useState(false);
    const [message, setMessage] = useState({ type: '', text: '' });
    const [healthStatus, setHealthStatus] = useState({});
    const [checkingHealth, setCheckingHealth] = useState({});

    const handleAddAccount = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setMessage({ type: '', text: '' });
        try {
            await authedFetch(`${API_URL}/accounts/add`, {
                method: 'POST',
                body: JSON.stringify({ username: newUsername, password: newPassword })
            });
            setMessage({ type: 'success', text: 'Hesap başarıyla eklendi!' });
            setNewUsername('');
            setNewPassword('');
            onUpdate();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
        setIsSubmitting(false);
    };

    const handleAddAccountWithCookie = async (e) => {
        e.preventDefault();
        setIsSubmittingCookie(true);
        setMessage({ type: '', text: '' });
        try {
            await authedFetch(`${API_URL}/accounts/add-with-cookie`, {
                method: 'POST',
                body: JSON.stringify({ username: cookieUsername, cookie: cookieValue })
            });
            setMessage({ type: 'success', text: 'Hesap cookie ile başarıyla eklendi!' });
            setCookieUsername('');
            setCookieValue('');
            onUpdate();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
        setIsSubmittingCookie(false);
    };

    const handleDeleteAccount = async (usernameToDelete) => {
        if (!window.confirm(`'${usernameToDelete}' hesabını silmek istediğinizden emin misiniz? Bu işlem geri alınamaz.`)) return;
        setMessage({ type: '', text: '' });
        try {
            await authedFetch(`${API_URL}/accounts/delete/${usernameToDelete}`, { method: 'DELETE' });
            setMessage({ type: 'success', text: 'Hesap başarıyla silindi.' });
            onUpdate();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
    };

    const handleHealthCheck = async (username) => {
        setCheckingHealth(prev => ({ ...prev, [username]: true }));
        try {
            const res = await authedFetch(`${API_URL}/accounts/health-check/${username}`);
            const data = await res.json();
            setHealthStatus(prev => ({ ...prev, [username]: data }));
            if (data.status === 'repaired_with_cookie') {
                setMessage({ type: 'success', text: `${username}: ${data.message}` });
            }
        } catch (error) {
            setHealthStatus(prev => ({ ...prev, [username]: { status: 'error', message: error.message } }));
        }
        setCheckingHealth(prev => ({ ...prev, [username]: false }));
    };

    const getStatusChip = (username) => {
        const status = healthStatus[username];
        if (!status) return <Chip label="Bilinmiyor" size="small" />;
        if (status.status === 'ok' || status.status === 'repaired_with_cookie') return <Chip label="Sağlıklı" color="success" size="small" />;
        if (status.status === 'checkpoint_required') return <Chip label="Checkpoint Gerekli" color="warning" size="small" />;
        if (status.status === 'session_error') return <Chip label="Oturum Sorunu" color="warning" size="small" />;
        if (status.status === 'error') return <Chip label="Sorunlu" color="error" size="small" />;
        return <Chip label="Bilinmiyor" size="small" />;
    };

    const renderHealthCheckButton = (account) => {
        const username = account.username;
        const status = healthStatus[username];
    
        if (status && (status.status === 'session_error' || status.status === 'checkpoint_required')) {
            return (
                <Tooltip title="Oturumu onarmak için tıkla (kayıtlı cookie kullanılacak)">
                    <IconButton color="warning" onClick={() => handleHealthCheck(username)} disabled={checkingHealth[username]}>
                        {checkingHealth[username] ? <CircularProgress size={24} /> : <SyncIcon />}
                    </IconButton>
                </Tooltip>
            );
        }
    
        return (
            <Tooltip title={status?.message || "Hesap durumunu kontrol et"}>
                <IconButton color="primary" onClick={() => handleHealthCheck(username)} disabled={checkingHealth[username]}>
                    {checkingHealth[username] ? <CircularProgress size={24} /> : <HealthAndSafetyIcon />}
                </IconButton>
            </Tooltip>
        );
    };

    return (
        <Grid container spacing={4}>
            <Grid item xs={12} md={4}>
                <Paper>
                    <Typography variant="h6" gutterBottom>Yeni Instagram Hesabı Ekle</Typography>
                    <ToggleButtonGroup
                        color="primary"
                        value={loginMethod}
                        exclusive
                        onChange={(e, newMethod) => { if (newMethod) setLoginMethod(newMethod); }}
                        aria-label="login method"
                        fullWidth
                        sx={{ mb: 2 }}
                    >
                        <ToggleButton value="password"><VpnKeyIcon sx={{ mr: 1 }} /> Şifre</ToggleButton>
                        <ToggleButton value="cookie"><CookieIcon sx={{ mr: 1 }} /> Cookie</ToggleButton>
                    </ToggleButtonGroup>

                    {loginMethod === 'password' ? (
                        <Box component="form" onSubmit={handleAddAccount}>
                            <Stack spacing={2}>
                                <TextField label="Instagram Kullanıcı Adı" value={newUsername} onChange={e => setNewUsername(e.target.value)} fullWidth required />
                                <TextField label="Şifre" type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} fullWidth required />
                                <Button type="submit" variant="contained" fullWidth disabled={isSubmitting} startIcon={isSubmitting ? <CircularProgress size={20} color="inherit" /> : <AddCircleOutlineIcon />}>
                                    {isSubmitting ? 'Ekleniyor...' : 'Hesabı Ekle'}
                                </Button>
                            </Stack>
                        </Box>
                    ) : (
                        <Box component="form" onSubmit={handleAddAccountWithCookie}>
                            <Stack spacing={2}>
                                <TextField label="Instagram Kullanıcı Adı" value={cookieUsername} onChange={e => setCookieUsername(e.target.value)} fullWidth required helperText="Cookie'nin ait olduğu kullanıcı adı." />
                                <TextField label="Cookie Değeri" multiline rows={4} value={cookieValue} onChange={e => setCookieValue(e.target.value)} fullWidth required helperText="Tarayıcıdan alınan sessionid değerini yapıştırın." />
                                <Button type="submit" variant="contained" fullWidth disabled={isSubmittingCookie} startIcon={isSubmittingCookie ? <CircularProgress size={20} color="inherit" /> : <AddCircleOutlineIcon />}>
                                    {isSubmittingCookie ? 'Ekleniyor...' : 'Cookie ile Ekle'}
                                </Button>
                            </Stack>
                        </Box>
                    )}
                </Paper>
            </Grid>
            <Grid item xs={12} md={8}>
                <Paper>
                    <Typography variant="h6" gutterBottom>Yönetilen Hesaplarım</Typography>
                    {message.text && (<Alert severity={message.type} sx={{ my: 2 }} onClose={() => setMessage({ text: '' })}>{message.text}</Alert>)}
                    <TableContainer>
                        <Table>
                            <TableHead sx={{ bgcolor: 'action.hover' }}>
                                <TableRow>
                                    <TableCell>Kullanıcı Adı</TableCell>
                                    <TableCell>Durum</TableCell>
                                    <TableCell align="right">İşlemler</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {accounts.length > 0 ? accounts.map(account => (
                                    <TableRow key={account.username} hover>
                                        <TableCell component="th" scope="row"><Typography variant="body1" fontWeight="500">{account.username}</Typography></TableCell>
                                        <TableCell>{getStatusChip(account.username)}</TableCell>
                                        <TableCell align="right">
                                            {renderHealthCheckButton(account)}
                                            <Tooltip title="Hesabı Sil"><IconButton color="error" onClick={() => handleDeleteAccount(account.username)}><DeleteIcon /></IconButton></Tooltip>
                                        </TableCell>
                                    </TableRow>
                                )) : (
                                    <TableRow>
                                        <TableCell colSpan={3} align="center">Henüz eklenmiş bir hesap bulunmuyor.</TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </Paper>
            </Grid>
        </Grid>
    );
}

function VeriToplamaPage({ accounts, authedFetch }) {
    const [collectionType, setCollectionType] = useState('followers');
    const [performer, setPerformer] = useState('');
    const [target, setTarget] = useState('');
    const [minFollowers, setMinFollowers] = useState('');
    const [requireContactInfo, setRequireContactInfo] = useState(false);
    
    const [jobId, setJobId] = useState(null);
    const [jobStatus, setJobStatus] = useState(null);
    const [message, setMessage] = useState({ type: '', text: '' });

    const handleTypeChange = (event, newType) => {
        if (newType) {
            setCollectionType(newType);
            setTarget('');
        }
    };

    const getTargetLabel = () => {
        switch (collectionType) {
            case 'followers': return 'Hedef Kullanıcı Adı';
            case 'likers': return 'Hedef Gönderi Linki';
            case 'hashtag': return 'Hedef Hashtag (örn: #teknoloji)';
            default: return 'Hedef';
        }
    };

    useEffect(() => {
        if (!jobId) return;
        const interval = setInterval(async () => {
            try {
                const res = await authedFetch(`${API_URL}/jobs/status/${jobId}`);
                const data = await res.json();
                setJobStatus(data);
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    setJobId(null);
                }
            } catch (error) {
                console.error("İşlem durumu alınamadı:", error);
                clearInterval(interval);
            }
        }, 3000);
        return () => clearInterval(interval);
    }, [jobId, authedFetch]);

    const handleStartCollection = async (e) => {
        e.preventDefault();
        setMessage({ type: '', text: '' });
        setJobStatus(null);
        try {
            const res = await authedFetch(`${API_URL}/collection/start`, {
                method: 'POST',
                body: JSON.stringify({ 
                    performerUsername: performer, 
                    collectionType,
                    target,
                    minFollowers,
                    requireContactInfo
                })
            });
            const data = await res.json();
            setMessage({ type: 'success', text: data.message });
            setJobId(data.jobId);
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
    };

    return (
        <Paper sx={{ p: 4 }}>
            <Typography variant="h5" gutterBottom>Gelişmiş Veri Toplama</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Farklı kaynaklardan hedef kitlenizi toplayın ve gelişmiş filtreler uygulayarak veri havuzunuzu oluşturun.
            </Typography>

            <Box component="form" onSubmit={handleStartCollection}>
                <Stack spacing={3}>
                    <FormControl fullWidth required>
                        <InputLabel>İşlemi Yapacak Hesap</InputLabel>
                        <Select value={performer} label="İşlemi Yapacak Hesap" onChange={e => setPerformer(e.target.value)}>
                            {accounts.map(acc => <MenuItem key={acc.username} value={acc.username}>{acc.username}</MenuItem>)}
                        </Select>
                    </FormControl>

                    <ToggleButtonGroup
                        color="primary"
                        value={collectionType}
                        exclusive
                        onChange={handleTypeChange}
                        aria-label="collection type"
                    >
                        <ToggleButton value="followers"><PeopleAltIcon sx={{mr:1}}/> Takipçiler</ToggleButton>
                        <ToggleButton value="likers"><FavoriteIcon sx={{mr:1}}/> Beğenenler</ToggleButton>
                        <ToggleButton value="hashtag"><TagIcon sx={{mr:1}}/> Hashtag</ToggleButton>
                    </ToggleButtonGroup>

                    <TextField label={getTargetLabel()} value={target} onChange={e => setTarget(e.target.value)} fullWidth required />
                    
                    <Divider>FİLTRELER (İsteğe Bağlı)</Divider>

                    <Grid container spacing={2}>
                        <Grid item xs={12} sm={6}>
                            <TextField label="Hedeflerin Min. Takipçisi" type="number" value={minFollowers} onChange={e => setMinFollowers(e.target.value)} fullWidth />
                        </Grid>
                        <Grid item xs={12} sm={6} sx={{display: 'flex', alignItems: 'center'}}>
                             <FormControlLabel control={<Switch checked={requireContactInfo} onChange={e => setRequireContactInfo(e.target.checked)} />} label="Sadece E-posta veya Telefonu Olanlar" />
                        </Grid>
                    </Grid>
                    
                    <Box>
                        <Button type="submit" variant="contained" size="large" disabled={!!jobId}>
                            {jobId ? 'İşlem Sürüyor...' : 'Toplama İşlemini Başlat'}
                        </Button>
                    </Box>
                </Stack>
            </Box>
            
            {message.text && <Alert severity={message.type} sx={{ mt: 3 }}>{message.text}</Alert>}
            {jobStatus && (
                <Box sx={{ mt: 4, p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                    <Typography variant="h6" gutterBottom>İşlem Durumu</Typography>
                    <Chip label={jobStatus.status.toUpperCase()} color={jobStatus.status === 'completed' ? 'success' : (jobStatus.status === 'failed' ? 'error' : 'primary')} sx={{ mb: 2 }} />
                    <Typography variant="body1">{jobStatus.progress}</Typography>
                    {jobStatus.status === 'running' && <LinearProgress sx={{ mt: 2 }} />}
                </Box>
            )}
        </Paper>
    );
}

function VeriHavuzuPage({ authedFetch }) {
    const [users, setUsers] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [message, setMessage] = useState({ type: '', text: '' });

    const fetchCollectedData = useCallback(async () => {
        setIsLoading(true);
        try {
            const res = await authedFetch(`${API_URL}/collection/data`);
            const data = await res.json();
            if (data.success) {
                setUsers(data.users);
            }
        } catch (error) {
            setMessage({ type: 'error', text: `Veri alınamadı: ${error.message}` });
        }
        setIsLoading(false);
    }, [authedFetch]);

    useEffect(() => { fetchCollectedData(); }, [fetchCollectedData]);

    const handleClearData = async () => {
        if (!window.confirm(`Veri havuzundaki ${users.length} kullanıcının tamamı silinecek. Emin misiniz?`)) return;
        try {
            const res = await authedFetch(`${API_URL}/collection/data`, { method: 'DELETE' });
            const data = await res.json();
            setMessage({type: 'success', text: data.message});
            fetchCollectedData();
        } catch (error) {
            setMessage({type: 'error', text: `Hata: ${error.message}`});
        }
    }

    return (
        <Paper>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                <Typography variant="h5">Veri Havuzu ({users.length} Kullanıcı)</Typography>
                <Button variant="outlined" color="error" onClick={handleClearData} disabled={users.length === 0}>
                    Havuzu Temizle
                </Button>
            </Stack>
            {message.text && <Alert severity={message.type} sx={{ mb: 2 }}>{message.text}</Alert>}
            {isLoading ? <CircularProgress /> : (
                <TableContainer sx={{ maxHeight: 600 }}>
                    <Table stickyHeader>
                        <TableHead>
                            <TableRow><TableCell>Kullanıcı Adı</TableCell><TableCell>Tam Adı</TableCell><TableCell>Hesap Türü</TableCell></TableRow>
                        </TableHead>
                        <TableBody>
                            {users.map(user => (
                                <TableRow key={user.pk} hover>
                                    <TableCell>{user.username}</TableCell>
                                    <TableCell>{user.full_name}</TableCell>
                                    <TableCell>{user.is_private ? 'Gizli' : 'Açık'}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            )}
        </Paper>
    );
}

function TopluDmGonderPage({ accounts, authedFetch }) {
    const [performer, setPerformer] = useState('');
    const [messageText, setMessageText] = useState('');
    const [jobId, setJobId] = useState(null);
    const [jobStatus, setJobStatus] = useState(null);
    const [message, setMessage] = useState({ type: '', text: '' });
    const [dataPoolCount, setDataPoolCount] = useState(0);

    const [templates, setTemplates] = useState([]);
    const [newTemplateTitle, setNewTemplateTitle] = useState('');
    const [isSavingTemplate, setIsSavingTemplate] = useState(false);

    const fetchTemplates = useCallback(async () => {
        try {
            const res = await authedFetch(`${API_URL}/templates`);
            const data = await res.json();
            if (data.success) {
                setTemplates(data.templates);
            }
        } catch (error) {
            console.error("Şablonlar alınamadı:", error);
        }
    }, [authedFetch]);

    useEffect(() => {
        const fetchDataPoolCount = async () => {
            try {
                const res = await authedFetch(`${API_URL}/collection/data`);
                const data = await res.json();
                if (data.success) {
                    setDataPoolCount(data.count);
                }
            } catch (error) {
                console.error("Veri havuzu sayısı alınamadı:", error);
            }
        };
        fetchDataPoolCount();
        fetchTemplates();
    }, [authedFetch, fetchTemplates]);

    useEffect(() => {
        if (!jobId) return;
        const interval = setInterval(async () => {
            try {
                const res = await authedFetch(`${API_URL}/jobs/status/${jobId}`);
                const data = await res.json();
                setJobStatus(data);
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    setJobId(null);
                }
            } catch (error) {
                console.error("İşlem durumu alınamadı:", error);
                clearInterval(interval);
            }
        }, 3000);
        return () => clearInterval(interval);
    }, [jobId, authedFetch]);

    const handleStartSending = async (e) => {
        e.preventDefault();
        if (dataPoolCount === 0) {
            setMessage({ type: 'error', text: 'Veri havuzunuz boş. Lütfen önce veri toplayın.' });
            return;
        }
        setMessage({ type: '', text: '' });
        setJobStatus(null);
        try {
            const res = await authedFetch(`${API_URL}/dm/start`, {
                method: 'POST',
                body: JSON.stringify({ performerUsername: performer, messageText: messageText })
            });
            const data = await res.json();
            setMessage({ type: 'success', text: data.message });
            setJobId(data.jobId);
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
    };

    const handleSaveTemplate = async () => {
        if (!newTemplateTitle || !messageText) {
            setMessage({ type: 'error', text: 'Lütfen şablon başlığı ve mesaj metni girin.' });
            return;
        }
        setIsSavingTemplate(true);
        setMessage({ type: '', text: '' });
        try {
            await authedFetch(`${API_URL}/templates`, {
                method: 'POST',
                body: JSON.stringify({ title: newTemplateTitle, text: messageText })
            });
            setMessage({ type: 'success', text: 'Şablon başarıyla kaydedildi.' });
            setNewTemplateTitle('');
            fetchTemplates();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
        setIsSavingTemplate(false);
    };

    const handleDeleteTemplate = async (templateId) => {
        if (!window.confirm("Bu şablonu silmek istediğinizden emin misiniz?")) return;
        try {
            await authedFetch(`${API_URL}/templates/${templateId}`, { method: 'DELETE' });
            setMessage({ type: 'success', text: 'Şablon silindi.' });
            fetchTemplates();
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
    };

    return (
        <Grid container spacing={4}>
            <Grid item xs={12} md={7}>
                <Paper sx={{ p: 4 }}>
                    <Typography variant="h5" gutterBottom>Toplu DM Gönder</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Veri havuzunuzdaki kullanıcılara seçtiğiniz bir hesapla toplu direkt mesaj gönderin. Mesajınızda {'{username}'} ve {'{fullname}'} değişkenlerini kullanabilirsiniz.
                    </Typography>
                    <Alert severity="info" sx={{ mb: 3 }}>
                        Veri havuzunuzda gönderim için bekleyen **{dataPoolCount}** kullanıcı bulunmaktadır.
                    </Alert>

                    <Box component="form" onSubmit={handleStartSending}>
                        <Stack spacing={3}>
                            <FormControl fullWidth required>
                                <InputLabel>Mesajı Gönderecek Hesap</InputLabel>
                                <Select value={performer} label="Mesajı Gönderecek Hesap" onChange={e => setPerformer(e.target.value)}>
                                    {accounts.map(acc => <MenuItem key={acc.username} value={acc.username}>{acc.username}</MenuItem>)}
                                </Select>
                            </FormControl>
                            <TextField
                                label="Gönderilecek Mesaj Metni"
                                value={messageText}
                                onChange={e => setMessageText(e.target.value)}
                                fullWidth
                                required
                                multiline
                                rows={8}
                                placeholder="Merhaba {username}, nasılsın?"
                            />
                            <Button type="submit" variant="contained" size="large" disabled={!!jobId || dataPoolCount === 0}>
                                {jobId ? 'Gönderim Sürüyor...' : `Havuzdaki ${dataPoolCount} Kişiye Gönder`}
                            </Button>
                        </Stack>
                    </Box>
                    
                    {message.text && <Alert severity={message.type} sx={{ mt: 3 }}>{message.text}</Alert>}
                    {jobStatus && (
                        <Box sx={{ mt: 4, p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                            <Typography variant="h6" gutterBottom>Gönderim Durumu</Typography>
                            <Chip label={jobStatus.status.toUpperCase()} color={jobStatus.status === 'completed' ? 'success' : (jobStatus.status === 'failed' ? 'error' : 'primary')} sx={{ mb: 2 }} />
                            <Typography variant="body1">{jobStatus.progress}</Typography>
                            {jobStatus.status === 'running' && <LinearProgress sx={{ mt: 2 }} />}
                        </Box>
                    )}
                </Paper>
            </Grid>
            <Grid item xs={12} md={5}>
                <Paper sx={{ p: 3 }}>
                    <Typography variant="h6" gutterBottom>Mesaj Şablonları</Typography>
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle1" sx={{ mb: 1 }}>Yeni Şablon Kaydet</Typography>
                    <Stack spacing={2}>
                        <TextField label="Şablon Başlığı" size="small" value={newTemplateTitle} onChange={e => setNewTemplateTitle(e.target.value)} />
                        <Button onClick={handleSaveTemplate} variant="outlined" startIcon={<SaveIcon />} disabled={isSavingTemplate || !messageText}>
                            Mevcut Mesajı Şablon Olarak Kaydet
                        </Button>
                    </Stack>
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle1" sx={{ mb: 1 }}>Kayıtlı Şablonlar</Typography>
                    <Stack spacing={1}>
                        {templates.length > 0 ? templates.map(template => (
                            <Paper key={template.id} variant="outlined" sx={{ p: 1.5, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <Button startIcon={<ArticleIcon />} onClick={() => setMessageText(template.text)} sx={{ textTransform: 'none', justifyContent: 'flex-start' }}>
                                    {template.title}
                                </Button>
                                <Tooltip title="Şablonu Sil">
                                    <IconButton size="small" color="error" onClick={() => handleDeleteTemplate(template.id)}>
                                        <DeleteIcon fontSize="small" />
                                    </IconButton>
                                </Tooltip>
                            </Paper>
                        )) : <Typography color="text.secondary" variant="body2">Henüz kayıtlı şablon yok.</Typography>}
                    </Stack>
                </Paper>
            </Grid>
        </Grid>
    );
}

function HesapIsitmaPage({ accounts, authedFetch }) {
    const [performer, setPerformer] = useState('');
    const [jobId, setJobId] = useState(null);
    const [jobStatus, setJobStatus] = useState(null);
    const [message, setMessage] = useState({ type: '', text: '' });

    useEffect(() => {
        if (!jobId) return;
        const interval = setInterval(async () => {
            try {
                const res = await authedFetch(`${API_URL}/jobs/status/${jobId}`);
                const data = await res.json();
                setJobStatus(data);
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    setJobId(null);
                }
            } catch (error) {
                console.error("İşlem durumu alınamadı:", error);
                clearInterval(interval);
            }
        }, 3000);
        return () => clearInterval(interval);
    }, [jobId, authedFetch]);

    const handleStartWarming = async (e) => {
        e.preventDefault();
        setMessage({ type: '', text: '' });
        setJobStatus(null);
        try {
            const res = await authedFetch(`${API_URL}/warming/start`, {
                method: 'POST',
                body: JSON.stringify({ performerUsername: performer })
            });
            const data = await res.json();
            setMessage({ type: 'success', text: data.message });
            setJobId(data.jobId);
        } catch (error) {
            setMessage({ type: 'error', text: `Hata: ${error.message}` });
        }
    };

    return (
        <Paper sx={{ p: 4, maxWidth: 800, margin: 'auto' }}>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
                <Avatar sx={{ bgcolor: 'error.main', color: 'white' }}><LocalFireDepartmentIcon /></Avatar>
                <Typography variant="h5">Hesap Isıtma</Typography>
            </Stack>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Yeni eklediğiniz veya uzun süre kullanmadığınız hesapların etkileşimini artırarak spam riskini azaltın. Bu işlem, seçilen hesapla ana sayfadaki gönderileri beğenme gibi rastgele eylemler gerçekleştirir.
            </Typography>

            <Box component="form" onSubmit={handleStartWarming}>
                <Grid container spacing={3} alignItems="center">
                    <Grid item xs={12} sm={8}>
                        <FormControl fullWidth required>
                            <InputLabel>Isıtılacak Hesap</InputLabel>
                            <Select value={performer} label="Isıtılacak Hesap" onChange={e => setPerformer(e.target.value)}>
                                {accounts.map(acc => <MenuItem key={acc.username} value={acc.username}>{acc.username}</MenuItem>)}
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid item xs={12} sm={4}>
                        <Button type="submit" variant="contained" size="large" disabled={!!jobId} fullWidth>
                            {jobId ? 'İşlem Sürüyor...' : 'Isıtmayı Başlat'}
                        </Button>
                    </Grid>
                </Grid>
            </Box>
            
            {message.text && <Alert severity={message.type} sx={{ mt: 3 }}>{message.text}</Alert>}

            {jobStatus && (
                <Box sx={{ mt: 4, p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                    <Typography variant="h6" gutterBottom>İşlem Durumu</Typography>
                    <Chip label={jobStatus.status.toUpperCase()} color={jobStatus.status === 'completed' ? 'success' : (jobStatus.status === 'failed' ? 'error' : 'primary')} sx={{ mb: 2 }} />
                    <Typography variant="body1">{jobStatus.progress}</Typography>
                    {jobStatus.status === 'running' && <LinearProgress sx={{ mt: 2 }} />}
                </Box>
            )}
        </Paper>
    );
}

function JobHistoryPage({ authedFetch }) {
    const [history, setHistory] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchHistory = async () => {
            setIsLoading(true);
            try {
                const res = await authedFetch(`${API_URL}/jobs/history`);
                const data = await res.json();
                if (data.success) {
                    setHistory(data.history);
                }
            } catch (error) {
                console.error("İşlem geçmişi alınamadı:", error);
            }
            setIsLoading(false);
        };
        fetchHistory();
    }, [authedFetch]);

    const getStatusChip = (status) => {
        if (status === 'completed') return <Chip label="Başarılı" color="success" size="small" />;
        if (status === 'failed') return <Chip label="Başarısız" color="error" size="small" />;
        return <Chip label={status} size="small" />;
    };

    return (
        <Paper>
            <Typography variant="h5" sx={{ p: 2 }}>İşlem Geçmişi</Typography>
            <TableContainer>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>İşlem Türü</TableCell>
                            <TableCell>Başlangıç</TableCell>
                            <TableCell>Bitiş</TableCell>
                            <TableCell>Durum</TableCell>
                            <TableCell>Sonuç / İlerleme</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {isLoading ? (
                            <TableRow><TableCell colSpan={5} align="center"><CircularProgress /></TableCell></TableRow>
                        ) : (
                            history.map(job => (
                                <TableRow key={job.id}>
                                    <TableCell>{job.type}</TableCell>
                                    <TableCell>{new Date(job.startedAt).toLocaleString()}</TableCell>
                                    <TableCell>{job.finishedAt ? new Date(job.finishedAt).toLocaleString() : '-'}</TableCell>
                                    <TableCell>{getStatusChip(job.status)}</TableCell>
                                    <TableCell>{job.progress}</TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </TableContainer>
        </Paper>
    );
}


function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token'));
  const [user, setUser] = useState(() => { try { return JSON.parse(localStorage.getItem('user')); } catch { return null; } });
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [clientAccounts, setClientAccounts] = useState([]);
  const isLoggedIn = !!token;
  const theme = useMemo(() => getTheme('light'), []);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
  }, []);

  const authedFetch = useCallback(async (url, options = {}) => {
    try {
        const headers = { 'Content-Type': 'application/json', ...options.headers, 'Authorization': `Bearer ${token}`};
        const response = await fetch(url, { ...options, headers });
        if (response.status === 401) { 
            handleLogout(); 
            throw new Error('Oturum süresi doldu veya yetki reddedildi.'); 
        }
        if (!response.ok) { 
            const message = await getErrorMessage(response);
            throw new Error(message); 
        }
        return response;
    } catch (error) {
        if (error instanceof TypeError) {
            throw new Error('Sunucuya ulaşılamıyor. Backend sunucusunun çalıştığından emin olun.');
        }
        throw error;
    }
  }, [token, handleLogout]);

  const handleLoginSuccess = (newToken, role, name) => {
    const userData = { role, name };
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(userData));
    setToken(newToken);
    setUser(userData);
    setActiveTab(role === 'admin' ? 'Müşteri Yönetimi' : 'Dashboard');
  };

  const fetchClientData = useCallback(async () => {
    if (user?.role !== 'client') return;
    try {
        const accRes = await authedFetch(`${API_URL}/accounts/list`);
        const accData = await accRes.json();
        if (accData.success) setClientAccounts(accData.accounts);
    } catch (error) {
        console.error("Müşteri verileri çekilirken hata:", error);
    }
  }, [user, authedFetch]);

  useEffect(() => {
    if (isLoggedIn) {
        fetchClientData();
    } else {
      setClientAccounts([]);
    }
  }, [isLoggedIn, fetchClientData]);
  
  const adminMenuItems = [ { text: 'Dashboard', icon: <DashboardIcon /> }, { text: 'Müşteri Yönetimi', icon: <GroupIcon /> }, { text: 'İşlem Geçmişi', icon: <HistoryIcon /> }, { text: 'Ayarlar', icon: <SettingsIcon /> }];
  const clientMenuItems = [ 
    { text: 'Dashboard', icon: <DashboardIcon /> }, 
    { text: 'Hesaplarım', icon: <PeopleAltIcon /> },
    { text: 'Hesap Isıtma', icon: <LocalFireDepartmentIcon /> },
    { text: 'Veri Toplama', icon: <DataSaverOnIcon /> },
    { text: 'Veri Havuzu', icon: <StorageIcon /> }, 
    { text: 'Toplu DM Gönder', icon: <SendIcon /> }, 
    { text: 'İşlem Geçmişi', icon: <HistoryIcon /> },
    { text: 'Ayarlar', icon: <SettingsIcon /> } 
  ];
  const menuItems = user?.role === 'admin' ? adminMenuItems : clientMenuItems;

  const renderContent = () => {
    if (!user) return null;
    if (user.role === 'admin') {
        switch (activeTab) {
            case 'Dashboard': return <AdminDashboardPage authedFetch={authedFetch} />;
            case 'Müşteri Yönetimi': return <AdminClientsPage authedFetch={authedFetch} />;
            case 'İşlem Geçmişi': return <JobHistoryPage authedFetch={authedFetch} />;
            case 'Ayarlar': return <AdminSettingsPage />;
            default: return <AdminDashboardPage authedFetch={authedFetch} />;
        }
    }
    if (user.role === 'client') {
        switch (activeTab) {
            case 'Dashboard': return <ClientDashboardPage authedFetch={authedFetch} />;
            case 'Hesaplarım': return <HesaplarPage accounts={clientAccounts} authedFetch={authedFetch} onUpdate={fetchClientData} />;
            case 'Hesap Isıtma': return <HesapIsitmaPage accounts={clientAccounts} authedFetch={authedFetch} />;
            case 'Veri Toplama': return <VeriToplamaPage accounts={clientAccounts} authedFetch={authedFetch} />;
            case 'Veri Havuzu': return <VeriHavuzuPage authedFetch={authedFetch} />;
            case 'Toplu DM Gönder': return <TopluDmGonderPage accounts={clientAccounts} authedFetch={authedFetch} />;
            case 'İşlem Geçmişi': return <JobHistoryPage authedFetch={authedFetch} />;
            case 'Ayarlar': return <ClientSettingsPage authedFetch={authedFetch} />;
            default: return <ClientDashboardPage authedFetch={authedFetch} />;
        }
    }
    return null;
  };

  return ( 
    <ThemeProvider theme={theme}> 
      <CssBaseline />
      {!isLoggedIn ? ( <LoginPage onLoginSuccess={handleLoginSuccess} /> ) : (
        <Box sx={{ display: 'flex' }}> 
          <Drawer variant="permanent" sx={{ width: drawerWidth, flexShrink: 0, [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' }, }}> 
            <Toolbar><Typography variant="h6" noWrap> {user?.name || 'Panel'} </Typography></Toolbar> 
            <List> {menuItems.map((item) => ( <ListItem key={item.text} disablePadding> <ListItemButton selected={activeTab === item.text} onClick={() => setActiveTab(item.text)}> <ListItemIcon>{item.icon}</ListItemIcon> <ListItemText primary={item.text} /> </ListItemButton> </ListItem> ))} </List> 
            <Box sx={{flexGrow: 1}} />
            <Tooltip title="Çıkış Yap"><IconButton onClick={handleLogout} sx={{m: 2}} color="error"><LogoutIcon /></IconButton></Tooltip>
          </Drawer> 
          <Box component="main" sx={{ flexGrow: 1, p: 3, backgroundColor: 'grey.100' }}> 
            <Toolbar />
            <Typography variant="h4" gutterBottom>{activeTab}</Typography> 
            {renderContent()} 
          </Box> 
        </Box>
      )}
    </ThemeProvider> 
  );
}

export default App;
