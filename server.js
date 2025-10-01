const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3001;

// middleware
app.use(express.json());
app.use(cors());

// database setup
const db = new sqlite3.Database('./password_manager.db');

// create tables
db.serialize(() => {
    
    })