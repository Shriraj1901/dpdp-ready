export default function Checkout() {
  return (
    <form action="/api/orders" method="post">
      <input name="fullName" placeholder="Full name" />
      <input name="email" type="email" placeholder="Email" />
      <input name="phone" type="tel" placeholder="Mobile number" />
      <input name="addressLine1" placeholder="Address" />
      <input name="pincode" placeholder="PIN code" />
      <button type="submit">Pay with Razorpay</button>
    </form>
  );
}
