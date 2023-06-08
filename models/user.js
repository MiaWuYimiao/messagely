/** User class for message.ly */
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (
            username,
            password,
            first_name,
            last_name,
            phone,
            join_at,
            last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    const results = await db.query(
        `SELECT password
          FROM users
          WHERE username = $1`,
        [username]
    );
    const user = results.rows[0];
    if (user) {
      if(await bcrypt.compare(password, user.password)) {
        return true;
      }
    }

    return false;
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const results = await db.query(
      `UPDATE users
        SET last_login_at = current_timestamp
        WHERE username = $1
        RETURNING username`,
      [username]
    );
    if (!results.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return results.rows[0];
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
         FROM users
         ORDER BY username`,
    );

    if(results.rows.length === 0) {
      throw new ExpressError("No user found", 404)
    }

    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const results = await db.query (
      `SELECT username,
              first_name,
              last_name,
              phone,
              join_at,
              last_login_at
       FROM users
        WHERE username = $1`,
      [username]
    );

    if(!results.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
    
    return results.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const results = await db.query(
      `SELECT m.id AS id, 
              u2.username,
              u2.first_name,
              u2.last_name,
              u2.phone,
              m.body, 
              m.sent_at, 
              m.read_at
        FROM messages AS m
        JOIN users AS u1
          ON u1.username = m.from_username
        JOIN users AS u2
          ON u2.username = m.to_username
        WHERE m.from_username = $1`,
      [username]
    );

    if(results.rows.length === 0) {
      throw new ExpressError("No message from this user", 404)
    }

    return results.rows.map(m => ({
      id : m.id,
      to_user : {
        username : m.username,
        first_name : m.first_name,
        last_name : m.last_name,
        phone : m.phone,
        },
      body : m.body,
      sent_at : m.sent_at,
      read_at : m.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const results = await db.query(
      `SELECT m.id AS id, 
              u1.username,
              u1.first_name,
              u1.last_name,
              u1.phone,
              m.body, 
              m.sent_at, 
              m.read_at
        FROM messages AS m
        JOIN users AS u1
          ON u1.username = m.from_username
        JOIN users AS u2
          ON u2.username = m.to_username
        WHERE m.to_username = $1`,
      [username]
    );

    if(results.rows.length === 0) {
      throw new ExpressError("No message from this user", 404)
    }

    return results.rows.map(m => ({
      id : m.id,
      from_user : {
        username : m.username,
        first_name : m.first_name,
        last_name : m.last_name,
        phone : m.phone,
        },
      body : m.body,
      sent_at : m.sent_at,
      read_at : m.read_at,
    }));
  }
}


module.exports = User;