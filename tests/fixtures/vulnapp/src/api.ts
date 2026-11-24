import axios from 'axios';
import * as jwt from 'jsonwebtoken';
import { exec } from 'child_process';

const SECRET = "hardcoded-jwt-secret-123";

export async function handler(req, res) {
  const id = req.query.id;
  const rows = await pool.query(`SELECT * FROM t WHERE id = ${id}`); // JS-003
  exec("ls " + req.body.dir);                                          // JS-002
  const token = jwt.verify(req.headers.auth, "hardcoded-jwt-secret-123"); // JS-005
  const url = req.query.url;
  const r = await axios.get(url);                                      // JS-010
  const f = req.query.f;
  const data = fs.readFileSync("/var/data/" + f);                      // JS-011
  res.cookie('s', token, { httpOnly: false });
  return rows;
}
app.use(cors());
