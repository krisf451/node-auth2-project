const router = require("express").Router();
const bcrypt = require("bcryptjs");
const tokenBuilder = require("./token-builder");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const Users = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  let { username, password } = req.body;
  const { role_name } = req;
  const hash = bcrypt.hashSync(password, 6);
  Users.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;
  Users.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        //CREATING TOKEN AND APPEND IT TO RESPONSE HERE
        const token = tokenBuilder(user);
        res.status(200).json({
          message: `${user.username} is back`,
          token,
        });
      } else {
        next({ status: 401, message: "Invalid Credentials" });
      }
    })
    .catch(next);
});

module.exports = router;
