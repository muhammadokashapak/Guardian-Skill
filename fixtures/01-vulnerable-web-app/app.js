const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const q = req.query.q;
    // VULNERABILITY: Reflected XSS
    res.send(`<h1>Search results for: ${q}</h1>`);
});

app.get('/user', (req, res) => {
    const id = req.query.id;
    // VULNERABILITY: Raw SQL Injection
    const sql = `SELECT * FROM users WHERE id = '${id}'`;
    res.json({ query: sql });
});

module.exports = app;
