const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const q = req.query.q;
    // XSS Vulnerability
    res.send(`<h1>Search: ${q}</h1>`);
});

app.get('/user', (req, res) => {
    const id = req.query.id;
    // SQL Injection Vulnerability
    const sql = `SELECT * FROM users WHERE id = '${id}'`;
    res.json({ query: sql });
});

module.exports = app;
