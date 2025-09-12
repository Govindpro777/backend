import bcrypt from 'bcrypt';

async function hashAndVerify() {
    const plainPassword = "Govind@123"; // hardcoded password

    // 1️⃣ Hash the password with 12 salt rounds
    const hash = await bcrypt.hash(plainPassword, 12);
    console.log("Generated Hash:", hash);
    return;

    // 2️⃣ Verify the correct password
    const isMatch = await bcrypt.compare("Govind@123", hash);
    console.log("Correct password match?", isMatch); // true

    // 3️⃣ Verify with a wrong password
    const isWrong = await bcrypt.compare("wrongPassword", hash);
    console.log("Wrong password match?", isWrong); // false
}

hashAndVerify();