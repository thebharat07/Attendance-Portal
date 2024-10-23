var passport = require('passport');
var User = require('../models/user');
const MailSender = require('../mail');
var LocalStrategy = require('passport-local').Strategy;
const { validationResult } = require('express-validator'); // Assuming you're using express-validator

// Serialize and deserialize user for session management
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

// Email validation
function validateEmail(email) {
    const re = /^[a-zA-Z0-9._%+-]+@gvpce\.ac\.in$/; // This only allows GVPCE domain emails
    return re.test(email);
}

// Password validation
function validatePassword(password) {
    const errors = [];
    if (password.length < 6) {
        errors.push("Your password must be at least 6 characters.");
    }
    if (password.length > 15) {
        errors.push("Your password must be at most 15 characters.");
    }
    if (!/[A-Z]/.test(password)) {
        errors.push("Your password must contain at least one uppercase letter.");
    }
    if (!/[a-z]/.test(password)) {
        errors.push("Your password must contain at least one lowercase letter.");
    }
    if (!/[0-9]/.test(password)) {
        errors.push("Your password must contain at least one digit.");
    }
    if (!/[!@#$%^&*]/.test(password)) {
        errors.push("Your password must contain at least one special character.");
    }
    return errors;
}

// Local strategy for user registration
passport.use('local-register', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
},
    async function (req, email, password, done) {
        const { name, classs, rollnumber, teacher, student, year } = req.body;
        let messages = [];

        // Input validation
        req.checkBody('email', 'Invalid email').notEmpty().isEmail();
        req.checkBody('password', 'Invalid password').notEmpty();

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            errors.array().forEach(error => messages.push(error.msg));
            return done(null, false, req.flash('error', messages));
        }
        
        if (!validateEmail(email)) {
            messages.push("Email Domain: @gvpce.ac.in required");
            return done(null, false, req.flash('error', messages));
        }

        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return done(null, false, req.flash('error', passwordErrors));
        }

        if (!teacher && !student) {
            messages.push("Please check the tickbox");
            return done(null, false, req.flash('error', messages));
        }

        if (year === "Year") {
            messages.push("Please select a year");
            return done(null, false, req.flash('error', messages));
        }

        if (classs === "Class") {
            messages.push("Please select a class");
            return done(null, false, req.flash('error', messages));
        }

        try {
            // Check for rollnumber if provided
            if (rollnumber) {
                const existingUser = await User.findOne({ rollnumber });
                if (existingUser) {
                    return done(null, false, { message: 'Roll number already in use.' });
                }
            }

            // Check if email already exists
            const existingEmail = await User.findOne({ email });
            if (existingEmail) {
                return done(null, false, { message: 'Email already in use.' });
            }

            // Create and save the new user
            const newUser = new User({
                name,
                email,
                password: User.encryptPassword(password),
                class: classs,
                rollnumber: rollnumber || null,
                who: teacher ? "teacher" : "student",
                year: student ? year : null
            });

            await newUser.save();
            return done(null, newUser);

        } catch (err) {
            return done(err);
        }
    }
));

// Local strategy for user login
passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
},
    async function (req, email, password, done) {
        req.checkBody('email', 'Invalid Email').notEmpty().isEmail();
        req.checkBody('password', 'Invalid password').notEmpty();

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const messages = errors.array().map(err => err.msg);
            return done(null, false, req.flash('error', messages));
        }

        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'User not found.' });
            }

            if (!user.validPassword(password)) {
                return done(null, false, { message: 'Invalid Password' });
            }

            return done(null, user);

        } catch (err) {
            return done(err);
        }
    }
));
