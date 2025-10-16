import { useState, useEffect } from 'react';
import API from '../api/api';

function Dashboard() {
  const [website, setWebsite] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [passwords, setPasswords] = useState([]);
  const [showPasswords, setShowPasswords] = useState(false);
  const [masterPassword, setMasterPassword] = useState('');
  const [editingId, setEditingId] = useState(null); // currently editing password ID

  const fetchPasswords = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await API.get('/passwords', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPasswords(res.data);
    } catch (err) {
      alert('Failed to fetch passwords');
    }
  };

  useEffect(() => {
    fetchPasswords();
  }, []);

  const handleAddOrEditPassword = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('token');

    try {
      if (editingId) {
        // Edit existing password
        await API.put(`/passwords/${editingId}`, {
          service_name: website,
          username,
          password
        }, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setEditingId(null);
      } else {
        // Add new password
        await API.post('/passwords', {
          service_name: website,
          username,
          password
        }, {
          headers: { Authorization: `Bearer ${token}` }
        });
      }

      setWebsite('');
      setUsername('');
      setPassword('');
      fetchPasswords();
    } catch (err) {
      alert('Failed to save password');
    }
  };

  const handleEditClick = (p) => {
    setEditingId(p.id);
    setWebsite(p.service_name);
    setUsername(p.username);
    setPassword(p.password);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this password?')) return;

    try {
      const token = localStorage.getItem('token');
      await API.delete(`/passwords/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchPasswords();
    } catch {
      alert('Failed to delete password');
    }
  };

  const handleShowPasswords = () => {
    if (!masterPassword) {
      alert('Enter master password to view passwords');
      return;
    }
    setShowPasswords(!showPasswords);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    window.location.href = '/login';
  };

  return (
    <div className="w-full min-h-screen bg-gray-100 p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-4xl font-bold text-gray-800">Dashboard</h1>
        <button
          onClick={handleLogout}
          className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600 transition"
        >
          Logout
        </button>
      </div>

      {/* Add/Edit Password Form */}
      <form onSubmit={handleAddOrEditPassword} className="flex flex-col gap-4 max-w-md mx-auto bg-white p-6 rounded-xl shadow-md">
        <input
          type="text"
          placeholder="Website URL (https://example.com)"
          value={website}
          onChange={(e) => setWebsite(e.target.value)}
          className="p-3 border rounded placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-400"
          required
        />
        <input
          type="text"
          placeholder="Username / Email"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="p-3 border rounded placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-400"
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="p-3 border rounded placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-400"
          required
        />
        <button
          type="submit"
          className="bg-blue-500 text-white px-6 py-3 rounded hover:bg-blue-600 transition mt-2"
        >
          {editingId ? 'Save Changes' : 'Add Password'}
        </button>
      </form>

      {/* Master Password Input */}
      <div className="mt-8 max-w-md mx-auto flex flex-col gap-4">
        <input
          type="password"
          placeholder="Enter master password to reveal"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
          className="p-3 border rounded placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        <button
          onClick={handleShowPasswords}
          className="bg-green-500 text-white px-6 py-3 rounded hover:bg-green-600 transition"
        >
          {showPasswords ? 'Hide Passwords' : 'Show Passwords'}
        </button>
      </div>

      {/* Stored Passwords List */}
      <div className="mt-8 max-w-2xl mx-auto space-y-4">
        {passwords.map((p) => (
          <div key={p.id} className="bg-white p-4 rounded-xl shadow flex justify-between items-center">
            <a href={p.service_name || '#'} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">
              {p.service_name}
            </a>
            <span className="text-gray-700">{p.username}</span>
            <span className="text-gray-900">{showPasswords ? p.password : '••••••••'}</span>
            <div className="flex gap-2">
              <button
                onClick={() => handleEditClick(p)}
                className="bg-yellow-400 text-white px-3 py-1 rounded hover:bg-yellow-500 transition"
              >
                Edit
              </button>
              <button
                onClick={() => handleDelete(p.id)}
                className="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600 transition"
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Dashboard;
